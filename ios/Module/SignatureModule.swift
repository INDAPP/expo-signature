import ExpoModulesCore
import CryptoKit
import LocalAuthentication
import SwiftASN1

private let kKeySize = 256
let kEcASN1Header: [UInt8] = [
    /* sequence          */ 0x30, 0x59,
    /* |-> sequence      */ 0x30, 0x13,
    /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // (ANSI X9.62 public key type)
    /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // (ANSI X9.62 named elliptic curve)
    /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
]

public class SignatureModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoSignature")
        
        AsyncFunction("generateKeys", generateKeys)
        
        AsyncFunction("getPublicKey", getPublicKey)
        
        AsyncFunction("isKeyPresentInKeychain", isKeyPresentInKeychain)
        
        AsyncFunction("deleteKey", deleteKey)
        
        AsyncFunction("sign", sign)
        
        AsyncFunction("verify", verify)
        
        AsyncFunction("verifyWithKey", verifyWithKey)
    }
    
    @discardableResult
    internal func generateKeys(keySpec: KeySpec) throws -> Data {
        var error: Unmanaged<CFError>?
        
        if let publicKey = try getPublicKey(alias: keySpec.alias) {
            return publicKey
        }
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            throw error!.takeRetainedValue()
        }
        
        let attributes: NSMutableDictionary = [
            kSecAttrKeyType: keySpec.algorithm.type,
            kSecAttrKeySizeInBits: keySpec.size,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: keySpec.tag,
                kSecAttrAccessControl: access
            ]
        ]
#if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
#endif
        
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue()
        }
        
        return try getPublicKeyData(privateKey: privateKey)
    }
    
    internal func getPublicKey(alias: String) throws -> Data? {
        let (status, item) = queryForKey(alias: alias)
        
        guard status != errSecItemNotFound else {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        
        let publicKeyData = try? getPublicKeyData(privateKey: privateKey)
        
        return publicKeyData
    }
    
    private func getPublicKeyData(privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data else {
            throw error!.takeRetainedValue()
        }
        
        let attributes = SecKeyCopyAttributes(publicKey)!
        let keyType = (attributes as NSDictionary)[kSecAttrKeyType] as! CFString

        switch keyType {
        case kSecAttrKeyTypeECSECPrimeRandom:
            return Data(kEcASN1Header) + publicKeyData
        case kSecAttrKeyTypeRSA:
            return publicKeyData
        default:
            throw UnsupportedAlgorithm()
        }
    }
    
    internal func isKeyPresentInKeychain(alias: String) -> Bool {
        let (status, _) = queryForKey(alias: alias)
        
        return status == errSecSuccess
    }
    
    @discardableResult
    internal func deleteKey(alias: String) -> Bool {
        let tag = alias.data(using: .utf8)!
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
        ]
        
        let status = SecItemDelete(query)
        
        return status == errSecSuccess
    }
    
    internal func sign(data: Data, alias: String, info: SignaturePrompt) throws -> Data {
        let context = LAContext()
        let reason = [info.title, info.subtitle].compactMap { $0 }.joined(separator: "\n")
        context.localizedReason = reason
        context.localizedCancelTitle = info.cancel
        
        let (status, item) = self.queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        
        guard let algorithm: SecKeyAlgorithm = getKeyAlgorithm(key: privateKey),
              SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw UnsupportedAlgorithm()
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        
        return signature
    }
    
    internal func verify(data: Data, signature: Data, alias: String) throws -> Bool {
        let (status, item) = queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        
        
        guard let algorithm: SecKeyAlgorithm = getKeyAlgorithm(key: privateKey),
              SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw UnsupportedAlgorithm()
        }
        
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            throw error
        }
        
        return verified
    }
    
    internal func verifyWithKey(data: Data, signature: Data, publicKey: Data, algorithm: String) throws -> Bool {
        var type: CFString!
        
        switch algorithm {
        case "EC":
            type = kSecAttrKeyTypeECSECPrimeRandom
            break
        case "RSA":
            type = kSecAttrKeyTypeRSA
            break
        default:
            break
        }
        
        let parameters: NSDictionary = [
            kSecAttrKeyType: type!,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            publicKey as CFData,
            parameters as CFDictionary,
            &error
        ) else {
            throw error!.takeRetainedValue()
        }
        
        
        
        guard let algorithm: SecKeyAlgorithm = getKeyAlgorithm(key: key),
              SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            throw UnsupportedAlgorithm()
        }
        
        let verified = SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            throw error
        }
        
        return verified
    }
    
    private func queryForKey(alias: String, context: LAContext? = nil) -> (OSStatus, CFTypeRef?) {
        let tag = alias.data(using: .utf8)!
        
        let query: NSMutableDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        if let context = context {
            query[kSecUseAuthenticationContext] = context
        }
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
        return (status, item)
    }
    
    private func getKeyAlgorithm(key: SecKey) -> SecKeyAlgorithm? {
        guard let attributes = SecKeyCopyAttributes(key) else {
            return nil
        }
        
        guard let keyType = (attributes as NSDictionary)[kSecAttrKeyType] as? String else {
            return nil
        }
        
        switch keyType as CFString {
        case kSecAttrKeyTypeEC:
            return .ecdsaSignatureMessageX962SHA256
        case kSecAttrKeyTypeRSA:
            return .rsaSignatureMessagePKCS1v15SHA256
        default:
            return nil
        }
    }
    
}

private final class RetrieveKeyException: GenericException<OSStatus> {
    override var reason: String {
        "Key retrieval has failed with OSStatus code: \(param)"
    }
}

private final class UnsupportedAlgorithm: Exception {
    override var reason: String {
        "Algorithm not available for this key"
    }
}

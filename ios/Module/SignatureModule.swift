import ExpoModulesCore
import CryptoKit
import LocalAuthentication

private let kKeySize = 256

public class SignatureModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoSignature")
        
        AsyncFunction("generateKeys", generateKeys)
        
        AsyncFunction("getAlias", getAlias)
        
        AsyncFunction("getPublicKey", getPublicKey)
        
        AsyncFunction("isKeyPresentInKeychain", isKeyPresentInKeychain)
        
        AsyncFunction("deleteKey", deleteKey)
        
        AsyncFunction("sign", sign)
        
        AsyncFunction("verify", verify)
        
        AsyncFunction("verifyWithKey", verifyWithKey)
    }
    
    @discardableResult
    internal func generateKeys(keySpec: KeySpec) throws -> PublicKey {
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
                kSecAttrApplicationLabel: keySpec.tag,
                kSecAttrAccessControl: access
            ]
        ]
#if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
#endif
        
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue()
        }
        
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data else {
            throw error!.takeRetainedValue()
        }
        
        switch keySpec.algorithm {
        case .EC:
            return try PublicKey(ec: publicKeyData)
        case .RSA:
            return try PublicKey(rsa: publicKeyData)
        }
    }
    
    internal func getPublicKey(alias: String) throws -> PublicKey? {
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: alias,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
        guard status != errSecItemNotFound else {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
        
        guard let attributes = SecKeyCopyAttributes(publicKey) else {
            return nil
        }
        
        guard let keyType = (attributes as NSDictionary)[kSecAttrKeyType] as? String else {
            return nil
        }
        
        switch keyType as CFString {
        case kSecAttrKeyTypeEC:
            return try PublicKey(ec: publicKeyData)
        case kSecAttrKeyTypeRSA:
            return try PublicKey(rsa: publicKeyData)
        default:
            return nil
        }
        
    }
    
    internal func getAlias(publicKeyBase64: String) throws -> String? {
        let query: NSMutableDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecReturnAttributes: kCFBooleanTrue!,
            kSecAttrAccount: publicKeyBase64,
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        
        guard status == errSecSuccess, let attributes = item as? NSDictionary else {
            return nil
        }
        
        let uuidAlias = attributes[kSecAttrGeneric] as? String
        
        return uuidAlias
    }
    
    internal func isKeyPresentInKeychain(alias: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: alias,
            kSecReturnRef: kCFBooleanFalse!,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context,
        ]
        
        let status = SecItemCopyMatching(query, nil)
        
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }
    
    @discardableResult
    internal func deleteKey(alias: String) -> Bool {
        let tag = alias.data(using: .utf8)!
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: tag
        ]
        
        let status = SecItemDelete(query)
        
        return status == errSecSuccess
    }
    
    internal func sign(data: Data, alias: String, info: SignaturePrompt) throws -> Data {
        let context = LAContext()
        let reason = [info.title, info.subtitle].compactMap { $0 }.joined(separator: "\n")
        context.localizedReason = reason
        context.localizedCancelTitle = info.cancel
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: alias,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
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
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: alias,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
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
    
    internal func verifyWithKey(data: Data, signature: Data, publicKey: PublicKey) throws -> Bool {
        let keyData = try publicKey.asData()
        var type: CFString!
        if publicKey.x != nil, publicKey.y != nil {
            type = kSecAttrKeyTypeEC
        }
        if publicKey.n != nil, publicKey.e != nil {
            type = kSecAttrKeyTypeRSA
        }
        
        let parameters: NSDictionary = [
            kSecAttrKeyType: type!,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            keyData as CFData,
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



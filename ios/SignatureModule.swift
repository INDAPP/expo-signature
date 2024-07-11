import ExpoModulesCore
import CryptoKit
import BigInt
import LocalAuthentication

private let kKeySize = 256

public class SignatureModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoSignature")
        
        AsyncFunction("generateEllipticCurveKeys", generateEllipticCurveKeys)
        
        AsyncFunction("getEllipticCurvePublicKey", getEllipticCurvePublicKey)
        
        AsyncFunction("isKeyPresentInKeychain", isKeyPresentInKeychain)
        
        AsyncFunction("deleteKey", deleteKey)
        
        AsyncFunction("sign", sign)
        
        AsyncFunction("verify", verify)
        
        AsyncFunction("verifyWithKey", verifyWithKey)
    }
    
    private func generateEllipticCurveKeys(alias: String) throws -> PublicKey {
        let tag = alias.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            throw error!.takeRetainedValue()
        }
        
        let attributes: NSMutableDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits: kKeySize,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
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
        
        return try PublicKey(data: publicKeyData)
    }
    
    private func getEllipticCurvePublicKey(alias: String) throws -> PublicKey? {
        let (status, item) = queryForKey(alias: alias)
        
        guard status != errSecItemNotFound else {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
        
        return try PublicKey(data: publicKeyData)
    }
    
    private func isKeyPresentInKeychain(alias: String) -> Bool {
        let (status, _) = queryForKey(alias: alias)
        
        return status == errSecSuccess
    }
    
    private func deleteKey(alias: String) -> Bool {
        let tag = alias.data(using: .utf8)!
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
        ]
        
        let status = SecItemDelete(query)
        
        return status == errSecSuccess
    }
    
    private func sign(data: Data, alias: String, info: SignaturePrompt) throws -> Data {
        let context = LAContext()
        let reason = [info.title, info.subtitle].compactMap { $0 }.joined(separator: "\n")
        context.localizedReason = reason
        context.localizedCancelTitle = info.cancel
        
        let (status, item) = self.queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw UnsupportedAlgorithm()
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        
        return signature
    }
    
    private func verify(data: Data, signature: Data, alias: String) throws -> Bool {
        let (status, item) = queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            throw RetrieveKeyException(status)
        }
        
        let privateKey = item as! SecKey
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw UnsupportedAlgorithm()
        }
        
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            throw error
        }
        
        return verified
    }
    
    private func verifyWithKey(data: Data, signature: Data, publicKey: PublicKey) throws -> Bool {
        let keyData = try publicKey.coordinatesAsData()
        
        let parameters: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: kKeySize,
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            keyData as CFData,
            parameters as CFDictionary,
            &error
        ) else {
            throw error!.takeRetainedValue()
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
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
            kSecAttrKeyType: kSecAttrKeyTypeEC,
        ]
        if let context = context {
            query[kSecUseAuthenticationContext] = context
        }
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
        return (status, item)
    }
    
}

private class RetrieveKeyException: GenericException<OSStatus> {
    override var reason: String {
        "Key retrieval has failed with OSStatus code: \(param)"
    }
}

private class UnsupportedAlgorithm: Exception {
    override var reason: String {
        "Algorithm not available for this key"
    }
}



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
    
    private func generateEllipticCurveKeys(alias: String, promise: Promise) {
        let tag = alias.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            promise.reject(.from(code: .invalidParameters, error: error!.takeRetainedValue()))
            return
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
            promise.reject(.from(code: .keyStoreError, error: error!.takeRetainedValue()))
            return
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            promise.reject(.from(code: .generalError, description: "Can't retrieve the public key"))
            return
        }
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data else {
            promise.reject(.from(code: .keyExportError, error: error!.takeRetainedValue()))
            return
        }
        
        do {
            let key = try PublicKey(data: publicKeyData)
            promise.resolve(key)
        } catch PublicKeyError.keyDataTooShort {
            promise.reject(.from(code: .invalidKey, description: "Data too short"))
        } catch PublicKeyError.invalidPublicKeyPrefix {
            promise.reject(.from(code: .invalidKey, description: "Invalid public key prefix"))
        } catch {
            promise.reject(.from(code: .invalidKey, description: "Unknow error in public key data"))
        }
    }
    
    private func getEllipticCurvePublicKey(alias: String, promise: Promise) {
        let (status, item) = queryForKey(alias: alias)
        
        guard status != errSecItemNotFound else {
            promise.resolve(nil)
            return
        }
        
        guard status == errSecSuccess else {
            promise.reject(.from(code: .keyStoreError, description: "Error retrieving key"))
            return
        }
        
        let privateKey = item as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            promise.reject(.from(code: .keyStoreError, description: "Can't recontruct the key"))
            return
        }
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
            promise.reject(.from(code: .keyExportError, description: "Can't export the key"))
            return
        }
        
        do {
            let key = try PublicKey(data: publicKeyData)
            promise.resolve(key)
        } catch PublicKeyError.keyDataTooShort {
            promise.reject(.from(code: .invalidKey, description: "Data too short"))
        } catch PublicKeyError.invalidPublicKeyPrefix {
            promise.reject(.from(code: .invalidKey, description: "Invalid public key prefix"))
        } catch {
            promise.reject(.from(code: .invalidKey, description: "Unknow error in public key data"))
        }
    }
    
    private func isKeyPresentInKeychain(alias: String, promise: Promise) {
        let (status, _) = queryForKey(alias: alias)
        
        promise.resolve(status == errSecSuccess)
    }
    
    private func deleteKey(alias: String, promise: Promise) {
        let tag = alias.data(using: .utf8)!
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
        ]
        
        let status = SecItemDelete(query)
        
        promise.resolve(status == errSecSuccess)
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
    
    private func sign(data: Data, info: SignatureInfo, promise: Promise) {
        let context = LAContext()
        let reason = [info.title, info.subtitle].compactMap { $0 }.joined(separator: "\n")
        context.localizedReason = reason
        context.localizedCancelTitle = info.cancel
        
        let (status, item) = self.queryForKey(alias: info.alias)
        
        guard status == errSecSuccess else {
            promise.reject(.from(code: .keyStoreError, description: "Error retrieving key"))
            return
        }
        
        let privateKey = item as! SecKey
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            promise.reject(.from(code: .noSuchAlgorithm, description: "Algorithm not available for this key"))
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            promise.reject(.from(code: .signatureError, error: error!.takeRetainedValue()))
            return
        }
        
        promise.resolve(signature)
        
    }
    
    private func verify(data: Data, signature: Data, alias: String, promise: Promise) {
        let (status, item) = queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            promise.reject(.from(code: .keyStoreError, description: "Error retrieving key"))
            return
        }
        
        let privateKey = item as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            promise.reject(.from(code: .keyStoreError, description: "Can't recontruct the key"))
            return
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            promise.reject(.from(code: .noSuchAlgorithm, description: "Algorithm not available for this key"))
            return
        }
        
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            promise.reject(.from(code: .signatureError, error: error))
            return
        }
        
        promise.resolve(verified)
    }
    
    private func verifyWithKey(data: Data, signature: Data, publicKey: PublicKey, promise: Promise) {
        guard let keyData = publicKey.coordinatesAsData() else {
            promise.reject(.from(code: .invalidKey, description: "Invalid public key data"))
            return
        }
        
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
            promise.reject(.from(code: .invalidKey, description: "Cannot create key with this data"))
            return
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            promise.reject(.from(code: .noSuchAlgorithm, description: "Algorithm not available for this key"))
            return
        }
        
        let verified = SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            promise.reject(.from(code: .signatureError, error: error))
            return
        }
        
        promise.resolve(verified)
    }
    
}

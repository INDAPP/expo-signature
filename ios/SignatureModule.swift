import ExpoModulesCore
import CryptoKit
import BigInt
import LocalAuthentication

private let kKeySize = 256

public class SignatureModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoSignature")
        
        AsyncFunction("generateEllipticCurveKeys") { (alias: String, promise: Promise) in
            do {
                let key = try generateEllipticCurveKeys(alias: alias)
                promise.resolve(key)
            } catch let error {
                promise.reject(error)
            }
        }
        
        AsyncFunction("getEllipticCurvePublicKey") { (alias: String, promise: Promise) in
            let key = getEllipticCurvePublicKey(alias: alias)
            promise.resolve(key)
        }
        
        AsyncFunction("isKeyPresentInKeychain") { (alias: String, promise: Promise) in
            let isPresent = isKeyPresentInKeychain(alias: alias)
            promise.resolve(isPresent)
        }
        
        AsyncFunction("deleteKey") { (alias: String, promise: Promise) in
            let deleted = deleteKey(alias: alias)
            promise.resolve(deleted)
        }
        
        AsyncFunction("sign") { (data: Data, info: SignatureInfo, promise: Promise) in
            sign(data: data, info: info, promise: promise)
        }
        
        AsyncFunction("verify") { (data: Data, signature: Data, alias: String, promise: Promise) in
            verify(data: data, signature: signature, alias: alias, promise: promise)
        }
        
        AsyncFunction("verifyWithKey") { (data: Data, signature: Data, publicKey: PublicKey, promise: Promise) in
            verifyWithKey(data: data, signature: signature, publicKey: publicKey, promise: promise)
        }
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
            throw error!.takeRetainedValue() as Error
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
            throw error!.takeRetainedValue() as Error
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SignatureError.noPublicKey
        }
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data else {
            throw error!.takeRetainedValue() as Error
        }
        
        return try PublicKey(data: publicKeyData)
    }
    
    private func getEllipticCurvePublicKey(alias: String) -> PublicKey? {
        let (status, item) = queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        let privateKey = item as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return nil
        }
        
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
            return nil
        }
        
        return try? PublicKey(data: publicKeyData)
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
            promise.reject(SignatureError.noKeyForThisAlias)
            return
        }
        
        let privateKey = item as! SecKey
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            promise.reject(SignatureError.unsupportedAlghoritm)
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            promise.reject(error!.takeRetainedValue() as Error)
            return
        }
        
        promise.resolve(signature)
        
    }
    
    private func verify(data: Data, signature: Data, alias: String, promise: Promise) {
        let (status, item) = queryForKey(alias: alias)
        
        guard status == errSecSuccess else {
            promise.reject(SignatureError.noKeyForThisAlias)
            return
        }
        
        let privateKey = item as! SecKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            promise.reject(SignatureError.noPublicKey)
            return
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            promise.reject(SignatureError.unsupportedAlghoritm)
            return
        }
        
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            promise.reject(error)
            return
        }
        
        promise.resolve(verified)
    }
    
    private func verifyWithKey(data: Data, signature: Data, publicKey: PublicKey, promise: Promise) {
        guard let keyData = publicKey.coordinatesAsData() else {
            promise.reject(SignatureError.invalidPublicKeyFormat)
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
            promise.reject(error!.takeRetainedValue())
            return
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            promise.reject(SignatureError.unsupportedAlghoritm)
            return
        }
        
        let verified = SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, &error)
        
        if let error = error?.takeRetainedValue() as? Error {
            promise.reject(error)
            return
        }
        
        promise.resolve(verified)
    }
    
}

enum SignatureError: Error {
    case noPublicKey
    case noKeyForThisAlias
    case unsupportedAlghoritm
    case invalidPublicKeyFormat
    case keyNotAdded
}

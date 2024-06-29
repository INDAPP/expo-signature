import ExpoModulesCore
import CryptoKit
import BigInt

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
    }
    
    private func generateEllipticCurveKeys(alias: String) throws -> PublicKey {
        let tag = alias.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryAny,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        
        let attributes: NSMutableDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
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
    
    private func queryForKey(alias: String) -> (OSStatus, CFTypeRef?) {
        let tag = alias.data(using: .utf8)!
        
        let query: NSDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecReturnRef: kCFBooleanTrue!,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query, &item)
        
        return (status, item)
    }
    
}

enum SignatureError: Error {
    case noPublicKey
}

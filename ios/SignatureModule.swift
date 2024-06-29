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
}

enum SignatureError: Error {
    case noPublicKey
}

//
//  SignatureModuleTests.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 18/07/24.
//

import XCTest
import ExpoModulesCore
@testable import SignatureModule

final class SignatureModuleTests: XCTestCase {
    let alias = "TestKeyAlias"
    let dataToSign = "Test Data To Sign".data(using: .utf8)!
    let signaturePrompt = SignaturePrompt()
    
    var module: SignatureModule!
    var ec256KeySpec: KeySpec!
    var rsa2048KeySpec: KeySpec!
    
    override func setUp() async throws {
        let context = AppContext()
        module = SignatureModule(appContext: context)
        ec256KeySpec = KeySpec(algorithm: .EC, alias: alias, size: 256)
        rsa2048KeySpec = KeySpec(algorithm: .RSA, alias: alias, size: 2048)
    }
    
    override func tearDownWithError() throws {
        module.deleteKey(alias: alias)
    }
    
    func testEcKeysGenerationType() throws {
        let publicKey = try module.generateKeys(keySpec: ec256KeySpec)
        
        XCTAssertTrue(publicKey is ECPublicKey, "Generated key type is not EC")
    }
    
    func testRsaKeysGenerationType() throws {
        let publicKey = try module.generateKeys(keySpec: rsa2048KeySpec)
        
        XCTAssertTrue(publicKey is RSAPublicKey, "Generated key type is not RSA")
    }
    
    func testEcPublicKeyData() throws {
        let publicKey = try module.generateKeys(keySpec: ec256KeySpec)
        
        XCTAssertNoThrow(try publicKey.asData(), "Can't convert public EC key to data")
    }
    
    func testRsaPublicKeyData() throws {
        let publicKey = try module.generateKeys(keySpec: rsa2048KeySpec)
        
        XCTAssertNoThrow(try publicKey.asData(), "Can't convert public RSA key to data")
    }
    
    func testEcPublicKeySize() throws {
        let publicKey = try module.generateKeys(keySpec: ec256KeySpec)
        let data = try publicKey.asData()
        
        XCTAssertEqual(data.count, 65)
    }
    
    func testRsaPublicKeySize() throws {
        let publicKey = try module.generateKeys(keySpec: rsa2048KeySpec)
        let data = try publicKey.asData()
        
        XCTAssertEqual(data.count, 270)
    }
    
    func testNoKeyRetrieval() throws {
        let publicKey = try module.getPublicKey(alias: alias)
        
        XCTAssertNil(publicKey, "Unknow key retrieved from keychain")
    }

    func testEcPublicKeyRetrieval() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        let publicKey = try module.getPublicKey(alias: alias)
        
        XCTAssertNotNil(publicKey, "Can't retrieve EC public key")
        XCTAssertTrue(publicKey is ECPublicKey, "Retrieved key type is not EC")
    }
    
    func testRsaPublicKeyRetrieval() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        let publicKey = try module.getPublicKey(alias: alias)
        
        XCTAssertNotNil(publicKey, "Can't retrieve RSA public key")
        XCTAssertTrue(publicKey is RSAPublicKey, "Retrieved key type is not RSA")
    }
    
    func testKeyAbsence() {
        let isPresent = module.isKeyPresentInKeychain(alias: alias)
        
        XCTAssertFalse(isPresent, "Key alias shouldn't be present in keychain")
    }
    
    func testEcPublicKeyPresence() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        let isPresent = module.isKeyPresentInKeychain(alias: alias)
        
        XCTAssertTrue(isPresent, "EC public key is not present in keychain")
    }
    
    func testRsaPublicKeyPresence() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        let isPresent = module.isKeyPresentInKeychain(alias: alias)
        
        XCTAssertTrue(isPresent, "RSA public key is not present in keychain")
    }
    
    func testEcKeyDeletion() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        let deleted = module.deleteKey(alias: alias)
        
        XCTAssertFalse(module.isKeyPresentInKeychain(alias: alias), "EC key still present after deletion")
        XCTAssertTrue(deleted, "Wrong EC key deletion return value")
    }
    
    func testRsaKeyDeletion() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        let deleted = module.deleteKey(alias: alias)
        
        XCTAssertFalse(module.isKeyPresentInKeychain(alias: alias), "RSA key still present after deletion")
        XCTAssertTrue(deleted, "Wrong RSA key deletion return value")
    }
    
    func testNoKeyDeletion() {
        let deleted = module.deleteKey(alias: alias)
        
        XCTAssertFalse(deleted, "Unexpected key deletion")
    }
    
    func testEcKeySigning() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        
        XCTAssertNoThrow(try module.sign(data: dataToSign, alias: alias, info: signaturePrompt), "Error in EC signing")
    }
    
    func testRsaKeySigning() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        
        XCTAssertNoThrow(try module.sign(data: dataToSign, alias: alias, info: signaturePrompt), "Error in RSA signing")
    }
    
    func testEcSigningDifference() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        let signature1 = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        let signature2 = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        
        XCTAssertNotEqual(signature1, signature2, "Multiple EC signatures should be different")
    }
    
    func testRsaSigningEquality() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        let signature1 = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        let signature2 = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        
        XCTAssertEqual(signature1, signature2, "Multiple RSA signatures should be equal")
    }
    
    func testEcKeyVerify() throws {
        try module.generateKeys(keySpec: ec256KeySpec)
        let signature = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        let verified = try module.verify(data: dataToSign, signature: signature, alias: alias)
        
        XCTAssertTrue(verified, "Cannot verify EC signed data")
    }
    
    func testRsaKeyVerify() throws {
        try module.generateKeys(keySpec: rsa2048KeySpec)
        let signature = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        let verified = try module.verify(data: dataToSign, signature: signature, alias: alias)
        
        XCTAssertTrue(verified, "Cannot verify RSA signed data")
    }
    
    func testExternalEcKeyVerify() throws {
        let publicKey = try module.generateKeys(keySpec: ec256KeySpec)
        let signature = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        module.deleteKey(alias: alias)
        let verified = try module.verifyWithKey(data: dataToSign, signature: signature, publicKey: Either(publicKey))
        
        XCTAssertTrue(verified, "Cannote verify data signed with external EC key")
    }
    
    func testExternalRsaKeyVerify() throws {
        let publicKey = try module.generateKeys(keySpec: rsa2048KeySpec)
        let signature = try module.sign(data: dataToSign, alias: alias, info: signaturePrompt)
        module.deleteKey(alias: alias)
        let verified = try module.verifyWithKey(data: dataToSign, signature: signature, publicKey: Either(publicKey))
        
        XCTAssertTrue(verified, "Cannote verify data signed with external RSA key")
    }
}

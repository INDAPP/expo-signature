//
//  PublicKey.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 29/06/24.
//

import ExpoModulesCore
import BigInt

protocol PublicKey: Record {
    init(data: Data) throws
    
    func asData() throws -> Data
}

struct ECPublicKey: PublicKey {
    init() {}
    
    @Field var x: String
    @Field var y: String
    
    init(data: Data) throws {
        let (xData, yData) = try data.toEcParams()
        
        x = BigUInt(xData).description
        y = BigUInt(yData).description
    }
    
    func asData() throws -> Data {
        guard let xInt = BigInt(x),
              let yInt = BigInt(y) else {
            throw PublicKeyException(.invalidCoordinates)
        }
        let xData = xInt.magnitude.serialize()
        let yData = yInt.magnitude.serialize()
        
        return try Data(x: xData, y: yData)
    }
}

struct RSAPublicKey: PublicKey {
    init() {}
    
    @Field var n: String
    @Field var e: String
    
    init(data: Data) throws {
        let (modulusData, exponentData) = try data.toRsaParams()
        
        n = BigUInt(modulusData).description
        e = BigUInt(exponentData).description
    }
    
    func asData() throws -> Data {
        guard let nInt = BigInt(n),
              let eInt = BigInt(e) else {
            throw PublicKeyException(.invalidCoordinates)
        }
        let modulusData = nInt.magnitude.serialize()
        let exponentData = eInt.magnitude.serialize()

        return Data(modulus: modulusData, exponent: exponentData)
    }
}

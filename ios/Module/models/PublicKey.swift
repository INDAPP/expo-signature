//
//  PublicKey.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 29/06/24.
//

import ExpoModulesCore
import BigInt

struct PublicKey: Record {
    @Field var x: String?
    @Field var y: String?
    
    @Field var n: String?
    @Field var e: String?
    
    init() {
        
    }
    
    init(data: Data) throws {
        if let (xData, yData) = try? data.toEcParams() {
            x = BigUInt(xData).description
            y = BigUInt(yData).description
        } else if let (modulusData, exponentData) = try? data.toRsaParams() {
            n = BigInt(modulusData).description
            e = BigUInt(exponentData).description
        } else {
            throw PublicKeyException(.invalidCoordinates)
        }
    }
    
    init(ec data: Data) throws {
        let (xData, yData) = try data.toEcParams()
        x = BigUInt(xData).description
        y = BigUInt(yData).description
    }
    
    init(rsa data: Data) throws {
        let (modulusData, exponentData) = try data.toRsaParams()
        n = BigInt(modulusData).description
        e = BigUInt(exponentData).description
    }
    
    func asData() throws -> Data {
        if let x = self.x, let y = self.y {
            guard let xInt = BigInt(x),
                  let yInt = BigInt(y) else {
                throw PublicKeyException(.invalidCoordinates)
            }
            let xData = xInt.magnitude.serialize()
            let yData = yInt.magnitude.serialize()
            
            return try Data(x: xData, y: yData)
        } else if let n = self.n, let e = self.e {
            guard let nInt = BigInt(n),
                  let eInt = BigUInt(e) else {
                throw PublicKeyException(.invalidCoordinates)
            }
            let modulusData = nInt.serialize()
            let exponentData = eInt.serialize()

            return Data(modulus: modulusData, exponent: exponentData)
        } else {
            throw PublicKeyException(.invalidCoordinates)
        }
    }
}

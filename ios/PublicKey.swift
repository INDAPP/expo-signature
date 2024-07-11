//
//  PublicKey.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 29/06/24.
//

import ExpoModulesCore
import BigInt

struct PublicKey: Record {
    init() {}
    
    @Field var x: String
    @Field var y: String
    
    init(data: Data) throws {
        guard data.count > 64 else {
            throw PublicKeyException(.keyDataTooShort)
        }
        guard data[0] == 0x04 else {
            throw PublicKeyException(.invalidPublicKeyPrefix)
        }
        
        let xData = data.subdata(in: 1..<33)
        let yData = data.subdata(in: 33..<65)
        x = BigUInt(xData).description
        y = BigUInt(yData).description
    }
    
    func coordinatesAsData() throws -> Data {
        guard let xInt = BigInt(x),
              let yInt = BigInt(y) else {
            throw PublicKeyException(.invalidCoordinates)
        }
        var data = Data([0x04])
        data.append(xInt.magnitude.serialize())
        data.append(yInt.magnitude.serialize())
        guard data.count > 64 else {
            throw PublicKeyException(.keyDataTooShort)
        }
        return Data(data)
    }
}

enum PublicKeyError: String {
    case keyDataTooShort = "Key data is too short"
    case invalidPublicKeyPrefix = "Invalid key prefix"
    case invalidCoordinates = "Invalid key coordinates"
}

private class PublicKeyException: GenericException<PublicKeyError> {
    override var reason: String {
        param.rawValue
    }
}

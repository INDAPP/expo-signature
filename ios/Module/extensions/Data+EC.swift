//
//  Data+EC.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 15/07/24.
//

extension Data {
    init(x: Data, y: Data) throws {
        var data = Data([0x04])
        data.append(x)
        data.append(y)
        guard data.count > 64 else {
            throw PublicKeyException(.keyDataTooShort)
        }
        self.init(data)
    }
    
    func toEcParams() throws -> (x: Data, y: Data) {
        guard first == 0x04 else {
            throw PublicKeyException(.invalidPublicKeyPrefix)
        }
        guard count > 64 else {
            throw PublicKeyException(.keyDataTooShort)
        }
        
        let coordinateData = dropFirst()
        let coordinateLength = coordinateData.count / 2
        
        let x = coordinateData.prefix(coordinateLength)
        let y = coordinateData.suffix(coordinateLength)
        
        return (x: Data(x), y: Data(y))
    }
}

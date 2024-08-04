//
//  Data+RSA.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 14/07/24.
//

extension Data {
    init(modulus: Data, exponent: Data) {
        var asn1Data = Data()
        
        // Modulus INTEGER
        var modulusData = Data([0x02]) // INTEGER tag
        modulusData.append(modulus.asn1Length)
        modulusData.append(modulus)
        
        // Exponent INTEGER
        var exponentData = Data([0x02]) // INTEGER tag
        exponentData.append(exponent.asn1Length)
        exponentData.append(exponent)
        
        // Combine modulus and exponent into a SEQUENCE
        var combinedData = Data()
        combinedData.append(modulusData)
        combinedData.append(exponentData)
        
        var sequenceData = Data([0x30]) // SEQUENCE tag
        sequenceData.append(combinedData.asn1Length)
        sequenceData.append(combinedData)
        
        asn1Data.append(sequenceData)
        
        self.init(asn1Data)
    }
    
    func toRsaParams() throws -> (modulus: Data, exponent: Data) {
        var index = 0
        
        // Check for SEQUENCE
        guard self[index] == 0x30 else {
            throw PublicKeyException(.invalidPublicKeyPrefix)
        }
        index += 1
        let _ = readAsn1Length(startingAt: &index) // Read and skip SEQUENCE length

        // Check for INTEGER (modulus)
        guard self[index] == 0x02 else {
            throw PublicKeyException(.invalidPublicKeyPrefix)
        }
        index += 1
        let modulusLength = readAsn1Length(startingAt: &index)
        let modulus = self[index..<(index + modulusLength)]
        index += modulusLength

        // Check for INTEGER (exponent)
        guard self[index] == 0x02 else {
            throw PublicKeyException(.invalidPublicKeyPrefix)
        }
        index += 1
        let exponentLength = readAsn1Length(startingAt: &index)
        let exponent = self[index..<(index + exponentLength)]
        index += exponentLength

        return (modulus: Data(modulus), exponent: Data(exponent))
    }
    
    private var asn1Length: Data {
        if count < 0x80 {
            return Data([UInt8(count)])
        } else if count < 0x100 {
            return Data([0x81, UInt8(count)])
        } else {
            return Data([0x82, UInt8(count >> 8), UInt8(count & 0xFF)])
        }
    }
    
    private func readAsn1Length(startingAt index: inout Int) -> Int {
        let lengthByte = self[index]
        index += 1
        
        if lengthByte & 0x80 == 0 {
            // Short form length
            return Int(lengthByte)
        } else {
            // Long form length
            let lengthOfLength = Int(lengthByte & 0x7F)
            let lengthData = self[index..<(index + lengthOfLength)]
            index += lengthOfLength
            
            var length = 0
            for byte in lengthData {
                length = (length << 8) + Int(byte)
            }
            return length
        }
    }
}

//
//  SignatureException.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 15/07/24.
//

import ExpoModulesCore

enum PublicKeyError: String {
    case keyDataTooShort = "Key data is too short"
    case invalidPublicKeyPrefix = "Invalid key prefix"
    case invalidCoordinates = "Invalid key coordinates"
}

class PublicKeyException: GenericException<PublicKeyError> {
    override var reason: String {
        param.rawValue
    }
}

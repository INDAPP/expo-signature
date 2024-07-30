//
//  SignatureAlgorithm.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 14/07/24.
//

import ExpoModulesCore

enum SignatureAlgorithm: String, Enumerable {
    case EC
    case RSA
}

extension SignatureAlgorithm {
    var type: CFString {
        switch self {
        case .EC:
            return kSecAttrKeyTypeEC
        case .RSA:
            return kSecAttrKeyTypeRSA
        }
    }
    
    
}

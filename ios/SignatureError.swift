//
//  SignatureError.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 11/07/24.
//

import ExpoModulesCore

enum SignatureError: String {
    case invalidParameters = "INVALID_PARAMETERS"
    case invalidKey = "INVALID_KEY"
    case keyStoreError = "KEY_STORE_ERROR"
    case noSuchAlgorithm = "NO_SUCH_ALGORITHM"
    case signatureError = "SIGNATURE_ERROR"
    case keyExportError = "KEY_EXPORT_ERROR"
    case generalError = "GENERAL_ERROR"
}

extension Exception {
    static func from(code: SignatureError, error: Error) -> Exception {
        return Exception(name: code.rawValue, description: error.localizedDescription).causedBy(error)
    }
    
    static func from(code: SignatureError, description: String) -> Exception {
        return Exception(name: code.rawValue, description: description)
    }
}

//
//  KeySpec.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 14/07/24.
//

import ExpoModulesCore

struct KeySpec: Record {
    @Field var algorithm: SignatureAlgorithm = .EC
    @Field var alias: String = "default_expo_signature_alias"
    @Field var size: Int = 256
}

extension KeySpec {
    var tag: Data {
        self.alias.data(using: .utf8)!
    }
}

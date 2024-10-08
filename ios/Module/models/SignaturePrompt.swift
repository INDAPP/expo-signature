//
//  SignatureInfo.swift
//  SignatureModule
//
//  Created by Riccardo Pizzoni on 05/07/24.
//

import ExpoModulesCore

struct SignaturePrompt: Record {
    @Field var title: String?
    @Field var subtitle: String?
    @Field var cancel: String?
}

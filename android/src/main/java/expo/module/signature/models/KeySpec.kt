package expo.module.signature.models

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

class KeySpec: Record {
    @Field val algorithm: SignatureAlgorithm = SignatureAlgorithm.EC
    @Field val alias: String = "default_expo_signature_alias"
    @Field val size: Int = 256
}


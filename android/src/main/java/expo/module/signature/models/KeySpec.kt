package expo.module.signature.models

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

data class KeySpec(
    @Field val algorithm: SignatureAlgorithm = SignatureAlgorithm.EC,
    @Field val alias: String = "default_expo_signature_alias",
    @Field val size: Int = 256,
): Record


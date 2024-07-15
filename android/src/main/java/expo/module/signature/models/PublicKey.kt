package expo.module.signature.models

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

sealed class PublicKey: Record

data class ECPublicKey(
    @Field val x: String,
    @Field val y: String,
) : PublicKey()

data class RSAPublicKey(
    @Field val n: String,
    @Field val e: String,
) : PublicKey()
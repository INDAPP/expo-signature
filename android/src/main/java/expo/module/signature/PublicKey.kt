package expo.module.signature

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

class PublicKey(
    @Field val x: String,
    @Field val y: String
) : Record
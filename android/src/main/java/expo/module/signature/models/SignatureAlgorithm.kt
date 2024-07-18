package expo.module.signature.models

import android.security.keystore.KeyProperties
import expo.modules.kotlin.types.Enumerable

enum class SignatureAlgorithm(val value: String): Enumerable {
    EC("EC"),
    RSA("RSA");

    val key: String
        get() = when (this) {
            EC -> KeyProperties.KEY_ALGORITHM_EC
            RSA -> KeyProperties.KEY_ALGORITHM_RSA
        }
}
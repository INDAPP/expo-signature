package expo.module.signature.models

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

class SignaturePrompt(
    @Field val title: String? = null,
    @Field val subtitle: String? = null,
    @Field val cancel: String? = null,
): Record {
    fun getPromptInfo(): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder().run {
        title?.let { setTitle(it) }
        subtitle?.let { setSubtitle(it) }
        cancel?.let { setNegativeButtonText(it) }
        setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        build()
    }
}
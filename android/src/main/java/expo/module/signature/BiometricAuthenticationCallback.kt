package expo.module.signature

import androidx.biometric.BiometricPrompt
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import java.security.SignatureException

class BiometricAuthenticationCallback(private val data: ByteArray, private val promise: Promise) :
    BiometricPrompt.AuthenticationCallback() {

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        val signature = result.cryptoObject?.signature ?: return promise.reject(
            CodedException("Signature not available")
        )
        try {
            signature.update(data)
            val signedData = signature.sign()
            promise.resolve(signedData)
        } catch (e: Exception) {
            val exception = when (e) {
                is SignatureException -> CodedException("Signature error", e)
                else -> CodedException("Unknown error", e)
            }
            promise.reject(exception)
        }
    }

    override fun onAuthenticationFailed() {
        promise.reject(CodedException("Unrecognized user"))
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        promise.reject(CodedException(errorCode.toString(), errString.toString(), null))
    }
}
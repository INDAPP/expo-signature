package expo.module.signature

import androidx.biometric.BiometricPrompt
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import java.security.SignatureException

class BiometricAuthenticationCallback(private val data: ByteArray, private val promise: Promise) :
    BiometricPrompt.AuthenticationCallback() {

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        val signature = result.cryptoObject?.signature ?: return promise.reject(
            CodedException(SignatureError.SIGNATURE_ERROR.code, "Signature not available", null)
        )
        try {
            signature.update(data)
            val signedData = signature.sign()
            promise.resolve(signedData)
        } catch (e: Exception) {
            val error = SignatureError.fromException(e)
            promise.reject(error.code, e.message, e)
        }
    }

    override fun onAuthenticationFailed() {
        promise.reject(
            CodedException(SignatureError.SIGNATURE_ERROR.code, "Unrecognized user", null)
        )
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        promise.reject(
            CodedException(SignatureError.SIGNATURE_ERROR.code, "Authentication failed with code $errorCode: $errString", null)
        )
    }
}
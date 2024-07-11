package expo.module.signature

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.UnrecoverableKeyException
import java.security.spec.InvalidParameterSpecException

enum class SignatureError(val code: String) {
    INVALID_PARAMETERS("INVALID_PARAMETERS"),
    INVALID_KEY("INVALID_KEY"),
    KEY_STORE_ERROR("KEY_STORE_ERROR"),
    NO_SUCH_ALGORITHM("NO_SUCH_ALGORITHM"),
    SIGNATURE_ERROR("SIGNATURE_ERROR"),
    KEY_EXPORT_ERROR("KEY_EXPORT_ERROR"),
    GENERAL_ERROR("GENERAL_ERROR");

    companion object {
        fun fromException(e: Exception): SignatureError {
            return when (e) {
                is InvalidAlgorithmParameterException, is InvalidParameterSpecException -> INVALID_PARAMETERS
                is InvalidKeyException -> INVALID_KEY
                is KeyStoreException, is UnrecoverableKeyException -> KEY_STORE_ERROR
                is NoSuchAlgorithmException -> NO_SUCH_ALGORITHM
                is SignatureException -> SIGNATURE_ERROR
                else -> GENERAL_ERROR
            }
        }
    }
}
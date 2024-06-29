package expo.module.signature

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPublicKey

const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val KEY_SIZE = 256

class SignatureModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("ExpoSignature")

        AsyncFunction("generateEllipticCurveKeys") { alias: String, promise: Promise ->
            try {
                val key = generateEllipticCurveKeys(alias)
                promise.resolve(key)
            } catch (e: Throwable) {
                promise.reject(CodedException(e))
            }
        }

        AsyncFunction("getEllipticCurvePublicKey") { alias: String, promise: Promise ->
            val key = getEllipticCurvePublicKey(alias)
            promise.resolve(key)
        }

        AsyncFunction("isKeyPresentInKeychain") { alias: String, promise: Promise ->
            val isPresent = isKeyPresentInKeychain(alias)
            promise.resolve(isPresent)
        }

        AsyncFunction("deleteKey") { alias: String, promise: Promise ->
            val deleted = deleteKey(alias)
            promise.resolve(deleted)
        }
    }

    private fun generateEllipticCurveKeys(alias: String): PublicKey {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(true)
            //setInvalidatedByBiometricEnrollment(false)
            setKeySize(KEY_SIZE)
            build()
        }

        generator.initialize(parameterSpec)
        val keyPair = generator.generateKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        return publicKey.w.run {
            PublicKey(affineX.toString(), affineY.toString())
        }
    }

    private fun getEllipticCurvePublicKey(alias: String): PublicKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey

        return publicKey?.w?.run {
            PublicKey(affineX.toString(), affineY.toString())
        }
    }

    private fun isKeyPresentInKeychain(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        return keyStore.isKeyEntry(alias)
    }

    private fun deleteKey(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.isKeyEntry(alias)) {
            keyStore.deleteEntry(alias)
            return true
        } else {
            return false
        }
    }
}

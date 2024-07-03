package expo.module.signature

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.core.interfaces.ActivityProvider
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.interfaces.ECPublicKey

const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val KEY_SIZE = 256

class SignatureModule : Module() {
    private lateinit var mActivityProvider: ActivityProvider

    private val keyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun definition() = ModuleDefinition {
        Name("ExpoSignature")

        OnCreate {
            mActivityProvider = appContext.activityProvider ?: throw CodedException(
                "Activity manager is unavailable"
            )
        }

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

        AsyncFunction("sign") { data: ByteArray, info: SignatureInfo, promise: Promise ->
            sign(data, info, promise)
        }
    }

    private fun generateEllipticCurveKeys(alias: String): PublicKey {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
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
        val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey

        return publicKey?.w?.run {
            PublicKey(affineX.toString(), affineY.toString())
        }
    }

    private fun isKeyPresentInKeychain(alias: String): Boolean {
        return keyStore.isKeyEntry(alias)
    }

    private fun deleteKey(alias: String): Boolean {
        val keyStore = this.keyStore

        if (keyStore.isKeyEntry(alias)) {
            keyStore.deleteEntry(alias)
            return true
        } else {
            return false
        }
    }

    private fun sign(data: ByteArray, info: SignatureInfo, promise: Promise) {
        val activity =
            mActivityProvider.currentActivity as? FragmentActivity ?: return promise.reject(
                CodedException("Not a FragmentActivity")
            )
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = BiometricAuthenticationCallback(data, promise)
        val prompt = BiometricPrompt(activity, executor, callback)

        val signature = try {
            val key = keyStore.getKey(info.alias, null) as PrivateKey
            Signature.getInstance("SHA256withECDSA").apply {
                initSign(key)
            }
        } catch (e: Exception) {
            val exception = when (e) {
                is KeyStoreException -> CodedException("Keystore not available", e)
                is NoSuchAlgorithmException -> CodedException("Signature not available", e)
                is UnrecoverableKeyException -> CodedException("Key not available", e)
                is InvalidKeyException -> CodedException("Invalid key", e)
                else -> CodedException("Unknown error", e)
            }
            return promise.reject(exception)
        }

        val cryptoObject = BiometricPrompt.CryptoObject(signature)
        val promptInfo = info.getPromptInfo()

        activity.runOnUiThread {
            prompt.authenticate(promptInfo, cryptoObject)
        }
    }
}

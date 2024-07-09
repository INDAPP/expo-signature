package expo.module.signature

import android.os.Build
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
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.UnrecoverableKeyException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidParameterSpecException


const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val KEY_SIZE = 256
const val CURVE_SPEC = "secp256r1"
const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

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

        AsyncFunction("verify") {
            data: ByteArray, signature: ByteArray, alias: String, promise: Promise ->
            verify(data, signature, alias, promise)
        }

        AsyncFunction("verifyWithKey") {
                data: ByteArray, signature: ByteArray, publicKey: PublicKey, promise: Promise ->
            verifyWithKey(data, signature, publicKey, promise)
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
            setKeySize(KEY_SIZE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(false)
            }
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
            Signature.getInstance(SIGNATURE_ALGORITHM).apply {
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

    private fun verify(data: ByteArray, signature: ByteArray, alias: String, promise: Promise) {
        try {
            val key = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
            val verified = Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(key)
                update(data)
                verify(signature)
            }
            promise.resolve(verified)
        } catch (e: Exception) {
            val exception = when (e) {
                is KeyStoreException -> CodedException("Keystore not available", e)
                is NoSuchAlgorithmException -> CodedException("Signature not available", e)
                is InvalidKeyException -> CodedException("Invalid key", e)
                is SignatureException -> CodedException("Signature error", e)
                else -> CodedException("Unknown error", e)
            }
            promise.reject(exception)
        }
    }

    private fun verifyWithKey(data: ByteArray, signature: ByteArray, publicKey: PublicKey, promise: Promise) {
        val xInt = BigInteger(publicKey.x)
        val yInt = BigInteger(publicKey.y)
        val ecPoint = ECPoint(xInt, yInt)

        try {
            val parameterSpec = AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
                init(ECGenParameterSpec(CURVE_SPEC));
                getParameterSpec(ECParameterSpec::class.java)
            }

            val publicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)

            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            val key = keyFactory.generatePublic(publicKeySpec)

            val verified = Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(key)
                update(data)
                verify(signature)
            }
            promise.resolve(verified)
        } catch (e: Exception) {
            val exception = when (e) {
                is NoSuchAlgorithmException -> CodedException("Signature not available", e)
                is InvalidKeyException -> CodedException("Invalid key", e)
                is SignatureException -> CodedException("Signature error", e)
                is InvalidParameterSpecException -> CodedException("Invalid parameter spec", e)
                else -> CodedException("Unknown error", e)
            }
            promise.reject(exception)
        }
    }

}

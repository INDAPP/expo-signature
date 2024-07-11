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
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec


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

        AsyncFunction("generateEllipticCurveKeys", this@SignatureModule::generateEllipticCurveKeys)

        AsyncFunction("getEllipticCurvePublicKey", this@SignatureModule::getEllipticCurvePublicKey)

        AsyncFunction("isKeyPresentInKeychain", this@SignatureModule::isKeyPresentInKeychain)

        AsyncFunction("deleteKey", this@SignatureModule::deleteKey)

        AsyncFunction("sign", this@SignatureModule::sign)

        AsyncFunction("verify", this@SignatureModule::verify)

        AsyncFunction("verifyWithKey", this@SignatureModule::verifyWithKey)
    }

    private fun generateEllipticCurveKeys(alias: String, promise: Promise) {
        try {
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
            val publicKey = (keyPair.public as ECPublicKey).w.run {
                PublicKey(affineX.toString(), affineY.toString())
            }
            promise.resolve(publicKey)
        } catch (e: Exception) {
            val error = SignatureError.fromException(e)
            promise.reject(error.code, e.message, e)
        }
    }

    private fun getEllipticCurvePublicKey(alias: String, promise: Promise) {
        try {
            val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
            val key = publicKey?.w?.run {
                PublicKey(affineX.toString(), affineY.toString())
            }

            promise.resolve(key)
        } catch (e: Exception) {
            val error = SignatureError.fromException(e)
            promise.reject(error.code, e.message, e)
        }
    }

    private fun isKeyPresentInKeychain(alias: String, promise: Promise) {
        try {
            val isPresent = keyStore.isKeyEntry(alias)
            promise.resolve(isPresent)
        } catch (e: Exception) {
            val error = SignatureError.fromException(e)
            promise.reject(error.code, e.message, e)
        }
    }

    private fun deleteKey(alias: String, promise: Promise) {
        try {
            val keyStore = this.keyStore

            if (keyStore.isKeyEntry(alias)) {
                keyStore.deleteEntry(alias)
                promise.resolve(true)
            } else {
                promise.resolve(false)
            }
        } catch (e: Exception) {
            val error = SignatureError.fromException(e)
            promise.reject(error.code, e.message, e)
        }
    }

    private fun sign(data: ByteArray, info: SignatureInfo, promise: Promise) {
        val activity =
            mActivityProvider.currentActivity as? FragmentActivity ?: return promise.reject(
                CodedException(SignatureError.SIGNATURE_ERROR.code, "Not a FragmentActivity", null)
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
            val error = SignatureError.fromException(e)
            return promise.reject(error.code, e.message, e)
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
            val error = SignatureError.fromException(e)
            return promise.reject(error.code, e.message, e)
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
            val error = SignatureError.fromException(e)
            return promise.reject(error.code, e.message, e)
        }
    }

}

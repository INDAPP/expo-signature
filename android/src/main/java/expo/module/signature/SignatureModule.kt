package expo.module.signature

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.core.interfaces.ActivityProvider
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine


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

        AsyncFunction("sign").Coroutine(this@SignatureModule::sign)

        AsyncFunction("verify", this@SignatureModule::verify)

        AsyncFunction("verifyWithKey", this@SignatureModule::verifyWithKey)
    }

    private fun generateEllipticCurveKeys(alias: String): PublicKey {
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

        val keyPair = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        ).run {
            initialize(parameterSpec)
            generateKeyPair()
        }

        val publicKey = (keyPair.public as ECPublicKey).w.run {
            PublicKey(affineX.toString(), affineY.toString())
        }

        return publicKey
    }

    private fun getEllipticCurvePublicKey(alias: String): PublicKey? {
        val key = keyStore.getCertificate(alias)?.publicKey ?: return null

        val publicKey = (key as ECPublicKey).w.run {
            PublicKey(affineX.toString(), affineY.toString())
        }

        return publicKey
    }

    private fun isKeyPresentInKeychain(alias: String): Boolean {
        return keyStore.isKeyEntry(alias)
    }

    private fun deleteKey(alias: String): Boolean {
        val keyStore = this.keyStore

        if (!keyStore.isKeyEntry(alias)) {
            return false
        }
        keyStore.deleteEntry(alias)

        return true
    }

    private suspend fun sign(data: ByteArray, info: SignatureInfo): ByteArray {
        val key = keyStore.getKey(info.alias, null) as PrivateKey
        val cryptoObject = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(key)
            BiometricPrompt.CryptoObject(this)
        }
        val promptInfo = info.getPromptInfo()

        return withContext(Dispatchers.Main) {
            suspendCoroutine { continuation ->
                val activity = mActivityProvider.currentActivity as FragmentActivity
                val executor = ContextCompat.getMainExecutor(activity)
                val prompt = BiometricPrompt(activity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val signature = result.cryptoObject!!.signature!!.run {
                                update(data)
                                sign()
                            }
                            continuation.resume(signature)
                        }

                        override fun onAuthenticationFailed() {
                            continuation.resumeWithException(AuthenticationFailedException())
                        }

                        override fun onAuthenticationError(
                            errorCode: Int, errString: CharSequence
                        ) {
                            continuation.resumeWithException(
                                AuthenticationErrorException(errorCode, errString)
                            )
                        }
                    })
                prompt.authenticate(promptInfo, cryptoObject)
            }
        }
    }

    private fun verify(data: ByteArray, signature: ByteArray, alias: String): Boolean {
        val key = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }

    private fun verifyWithKey(data: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        val xInt = BigInteger(publicKey.x)
        val yInt = BigInteger(publicKey.y)
        val ecPoint = ECPoint(xInt, yInt)

        val parameterSpec = AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
            init(ECGenParameterSpec(CURVE_SPEC));
            getParameterSpec(ECParameterSpec::class.java)
        }

        val publicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)

        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        val key = keyFactory.generatePublic(publicKeySpec)

        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }

}

internal class AuthenticationFailedException : CodedException("Unrecognized user")

internal class AuthenticationErrorException(errorCode: Int, errString: CharSequence) : CodedException("Authentication failed with code $errorCode: $errString")
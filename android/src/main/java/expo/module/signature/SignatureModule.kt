package expo.module.signature

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.module.signature.models.SignatureAlgorithm
import expo.module.signature.models.KeySpec
import expo.module.signature.models.SignaturePrompt
import expo.modules.core.interfaces.ActivityProvider
import expo.modules.kotlin.apifeatures.EitherType
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine


const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val CURVE_SPEC = "secp256r1"

class SignatureModule : Module() {
    private lateinit var mActivityProvider: ActivityProvider

    private val userAuthenticationRequired
        get() = true

    private val hasStrongBox: Boolean
        @RequiresApi(Build.VERSION_CODES.P) get() = appContext.reactContext!!.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE
        )

    private val keyStore get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @OptIn(EitherType::class)
    override fun definition() = ModuleDefinition {
        Name("ExpoSignature")

        OnCreate {
            mActivityProvider = appContext.activityProvider ?: throw CodedException(
                "Activity manager is unavailable"
            )
        }

        AsyncFunction("generateKeys", this@SignatureModule::generateKeys)

        AsyncFunction("getPublicKey", this@SignatureModule::getPublicKey)

        AsyncFunction("isKeyPresentInKeychain", this@SignatureModule::isKeyPresentInKeychain)

        AsyncFunction("deleteKey", this@SignatureModule::deleteKey)

        AsyncFunction("sign").Coroutine(this@SignatureModule::sign)

        AsyncFunction("verify", this@SignatureModule::verify)

        AsyncFunction("verifyWithKey", this@SignatureModule::verifyWithKey)
    }

    internal fun generateKeys(keySpec: KeySpec): ByteArray {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keySpec.alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            setUserAuthenticationRequired(userAuthenticationRequired)
            setKeySize(keySpec.size)
            if (keySpec.algorithm == SignatureAlgorithm.RSA) {
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && hasStrongBox) {
                setIsStrongBoxBacked(true)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(false)
            }
            build()
        }

        val keyPair = KeyPairGenerator.getInstance(
            keySpec.algorithm.key, ANDROID_KEYSTORE
        ).run {
            initialize(parameterSpec)
            generateKeyPair()
        }

        return keyPair.public.encoded
    }

    internal fun getPublicKey(alias: String): ByteArray? = keyStore.getCertificate(alias)?.publicKey?.encoded

    internal fun isKeyPresentInKeychain(alias: String): Boolean {
        return keyStore.isKeyEntry(alias)
    }

    internal fun deleteKey(alias: String): Boolean {
        val keyStore = this.keyStore

        if (!keyStore.isKeyEntry(alias)) {
            return false
        }
        keyStore.deleteEntry(alias)

        return true
    }

    internal suspend fun sign(data: ByteArray, alias: String, info: SignaturePrompt): ByteArray {
        val key = keyStore.getKey(alias, null) as PrivateKey

        val algorithm = getKeyAlgorithm(key)

        var cryptoObject = Signature.getInstance(algorithm).run {
            initSign(key)
            BiometricPrompt.CryptoObject(this)
        }

        if (userAuthenticationRequired) {
            val promptInfo = info.getPromptInfo()
            cryptoObject = authWithBiometric(cryptoObject, promptInfo)
        }

        return cryptoObject.signature!!.run {
            update(data)
            sign()
        }
    }

    private suspend fun authWithBiometric(
        cryptoObject: BiometricPrompt.CryptoObject, promptInfo: BiometricPrompt.PromptInfo
    ): BiometricPrompt.CryptoObject = withContext(Dispatchers.Main) {
        suspendCoroutine { continuation ->
            val activity = mActivityProvider.currentActivity as FragmentActivity
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        continuation.resume(result.cryptoObject!!)
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

    internal fun verify(data: ByteArray, signature: ByteArray, alias: String): Boolean {
        val key = keyStore.getCertificate(alias)?.publicKey!!

        val algorithm = getKeyAlgorithm(key)

        return Signature.getInstance(algorithm).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }

    internal fun verifyWithKey(
        data: ByteArray, signature: ByteArray, publicKey: ByteArray, algorithm: String
    ): Boolean {
        val spec = PKCS8EncodedKeySpec(publicKey)
        val key = when (algorithm) {
            "RSA" -> KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA).generatePublic(spec)
            "EC" -> KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(spec)
            else -> throw UnsupportedAlgorithmException()
        }

        val signatureAlgorithm = getKeyAlgorithm(key)

        return Signature.getInstance(signatureAlgorithm).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }

    private fun getKeyAlgorithm(key: Key): String {
        return when (key.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> "SHA256withECDSA"
            KeyProperties.KEY_ALGORITHM_RSA -> "SHA256withRSA"
            else -> throw UnsupportedAlgorithmException()
        }
    }
}

internal class AuthenticationFailedException : CodedException("Unrecognized user")

internal class AuthenticationErrorException(errorCode: Int, errString: CharSequence) :
    CodedException("Authentication failed with code $errorCode: $errString")

internal class UnsupportedAlgorithmException :
    CodedException("Algorithm not available for this key")
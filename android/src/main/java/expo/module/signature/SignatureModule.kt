package expo.module.signature

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.module.signature.models.SignatureAlgorithm
import expo.module.signature.models.KeySpec
import expo.module.signature.models.ECPublicKey
import expo.module.signature.models.PublicKey
import expo.module.signature.models.RSAPublicKey
import expo.module.signature.models.SignaturePrompt
import expo.modules.core.interfaces.ActivityProvider
import expo.modules.kotlin.apifeatures.EitherType
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.types.Either
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine


const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val CURVE_SPEC = "secp256r1"

class SignatureModule : Module() {
    internal lateinit var mActivityProvider: ActivityProvider

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

    internal fun generateKeys(keySpec: KeySpec): PublicKey {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keySpec.alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            if (keySpec.algorithm == SignatureAlgorithm.RSA) {
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            setUserAuthenticationRequired(true)
            setKeySize(keySpec.size)
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

        return when (val publicKey = keyPair.public) {
            is java.security.interfaces.ECPublicKey -> {
                publicKey.w.run {
                    ECPublicKey(affineX.toString(), affineY.toString())
                }
            }

            is java.security.interfaces.RSAPublicKey -> {
                publicKey.run {
                    RSAPublicKey(modulus.toString(), publicExponent.toString())
                }
            }

            else -> throw CodedException("Unsupported key type")
        }
    }

    internal fun getPublicKey(alias: String): PublicKey? {
        val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null

        return when (publicKey) {
            is java.security.interfaces.ECPublicKey -> {
                publicKey.w.run {
                    ECPublicKey(affineX.toString(), affineY.toString())
                }
            }

            is java.security.interfaces.RSAPublicKey -> {
                publicKey.run {
                    RSAPublicKey(modulus.toString(), publicExponent.toString())
                }
            }

            else -> null
        }
    }

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

        val cryptoObject = Signature.getInstance(algorithm).run {
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

    internal fun verify(data: ByteArray, signature: ByteArray, alias: String): Boolean {
        val key = keyStore.getCertificate(alias)?.publicKey!!

        val algorithm = getKeyAlgorithm(key)

        return Signature.getInstance(algorithm).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }

    @OptIn(EitherType::class)
    internal fun verifyWithKey(
        data: ByteArray,
        signature: ByteArray,
        publicKey: Either<ECPublicKey, RSAPublicKey>
    ): Boolean {
        val key = publicKey.get(ECPublicKey::class).let {
            val xInt = BigInteger(it.x)
            val yInt = BigInteger(it.y)
            val ecPoint = ECPoint(xInt, yInt)

            val parameterSpec =
                AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
                    init(ECGenParameterSpec(CURVE_SPEC));
                    getParameterSpec(ECParameterSpec::class.java)
                }

            val publicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)

            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            keyFactory.generatePublic(publicKeySpec)
        } ?: publicKey.get(RSAPublicKey::class).let {
            val modulus = BigInteger(it.n)
            val exponent = BigInteger(it.e)

            val publicKeySpec = RSAPublicKeySpec(modulus, exponent)

            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
            keyFactory.generatePublic(publicKeySpec)
        }


        val algorithm = getKeyAlgorithm(key)

        return Signature.getInstance(algorithm).run {
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
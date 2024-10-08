package expo.module.signature

import expo.module.signature.models.ECPublicKey
import expo.module.signature.models.KeySpec
import expo.module.signature.models.RSAPublicKey
import expo.module.signature.models.SignatureAlgorithm
import expo.module.signature.models.SignaturePrompt
import expo.modules.kotlin.apifeatures.EitherType
import expo.modules.kotlin.types.Either
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

@OptIn(EitherType::class)
inline fun <reified FirstType : Any, reified SecondType : Any> mockEitherFirstType(value: FirstType): Either<FirstType, SecondType> {
    val either = mockk<Either<FirstType, SecondType>>(relaxed = true)
    every { either.get(FirstType::class) } returns value
    every { either.`is`(FirstType::class) } returns true
    return either
}

@OptIn(EitherType::class)
inline fun <reified FirstType : Any, reified SecondType : Any> mockEitherSecondType(value: SecondType): Either<FirstType, SecondType> {
    val either = mockk<Either<FirstType, SecondType>>(relaxed = true)
    every { either.get(SecondType::class) } returns value
    every { either.`is`(SecondType::class) } returns true
    return either
}

class SignatureModuleTest {
    private val alias = "TestKeyAlias"
    private val dataToSign = "Test Data To Sign".toByteArray()
    private val signaturePrompt = SignaturePrompt(title = "Test prompt", cancel = "Cancel")

    private val ec256KeySpec = KeySpec(
        algorithm = SignatureAlgorithm.EC,
        alias = alias,
        size = 256,
    )
    private val rsa2048KeySpec = KeySpec(
        algorithm = SignatureAlgorithm.RSA,
        alias = alias,
        size = 2048,
    )

    private lateinit var module: SignatureModule

    @Before
    fun setUp() {
        module = spyk(SignatureModule(), recordPrivateCalls = true)
        every { module getProperty "hasStrongBox" } propertyType Boolean::class answers { false }
        every { module getProperty "userAuthenticationRequired" } propertyType Boolean::class answers { false }
    }

    @After
    fun tearDown() {
        module.deleteKey(alias)
    }

    @Test
    fun testEcKeysGenerationType() {
        val publicKey = module.generateKeys(ec256KeySpec)

        assertTrue("Generated key type is not EC", publicKey is ECPublicKey)
    }

    @Test
    fun testRsaKeysGenerationType() {
        val publicKey = module.generateKeys(rsa2048KeySpec)

        assertTrue("Generated key type is not RSA", publicKey is RSAPublicKey)
    }

    @Test
    fun testNoKeyRetrieval() {
        val publicKey = module.getPublicKey(alias)

        assertNull("Unknow key retrieved from keychain", publicKey)
    }

    @Test
    fun testEcPublicKeyRetrieval() {
        module.generateKeys(ec256KeySpec)
        val publicKey = module.getPublicKey(alias)

        assertNotNull("Can't retrieve EC public key", publicKey)
        assertTrue("Retrieved key type is not EC", publicKey is ECPublicKey)
    }

    @Test
    fun testRsaPublicKeyRetrieval() {
        module.generateKeys(rsa2048KeySpec)
        val publicKey = module.getPublicKey(alias)

        assertNotNull("Can't retrieve RSA public key", publicKey)
        assertTrue("Retrieved key type is not RSA", publicKey is RSAPublicKey)
    }

    @Test
    fun testKeyAbsence() {
        val isPresent = module.isKeyPresentInKeychain(alias)

        assertFalse("Key alias shouldn't be present in keychain", isPresent)
    }

    @Test
    fun testEcPublicKeyPresence() {
        module.generateKeys(ec256KeySpec)
        val isPresent = module.isKeyPresentInKeychain(alias)

        assertTrue("EC public key is not present in keychain", isPresent)
    }

    @Test
    fun testRsaPublicKeyPresence() {
        module.generateKeys(rsa2048KeySpec)
        val isPresent = module.isKeyPresentInKeychain(alias)

        assertTrue("RSA public key is not present in keychain", isPresent)
    }

    @Test
    fun testEcKeyDeletion() {
        module.generateKeys(ec256KeySpec)
        val deleted = module.deleteKey(alias)

        assertFalse(
            "EC key still present after deletion", module.isKeyPresentInKeychain(alias)
        )
        assertTrue("Wrong EC key deletion return value", deleted)
    }

    @Test
    fun testRsaKeyDeletion() {
        module.generateKeys(rsa2048KeySpec)
        val deleted = module.deleteKey(alias)

        assertFalse(
            "RSA key still present after deletion", module.isKeyPresentInKeychain(alias)
        )
        assertTrue("Wrong RSA key deletion return value", deleted)
    }

    @Test
    fun testNoKeyDeletion() {
        val deleted = module.deleteKey(alias)

        assertFalse("Unexpected key deletion", deleted)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testEcKeySigning() = runTest {
        module.generateKeys(ec256KeySpec)

        try {
            val signature = module.sign(
                dataToSign, alias, signaturePrompt
            )
            assertTrue("Unexpected signature length", signature.size >= 70)
            assertTrue("Unexpected signature length", signature.size <= 72)
        } catch (e: Exception) {
            fail("Error in EC signing")
        }
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testRsaKeySigning() = runTest {
        module.generateKeys(rsa2048KeySpec)

        try {
            val signature = module.sign(
                dataToSign, alias, signaturePrompt
            )
            assertEquals("Unexpected signature length", 256, signature.size)
        } catch (e: Exception) {
            fail("Error in RSA signing")
        }
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testEcSigningDifference() = runTest {
        module.generateKeys(ec256KeySpec)
        val signature1 = module.sign(dataToSign, alias, signaturePrompt)
        val signature2 = module.sign(dataToSign, alias, signaturePrompt)

        assertNotEquals(
            "Multiple EC signatures should be different", signature1, signature2
        )
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testRsaSigningEquality() = runTest {
        module.generateKeys(rsa2048KeySpec)
        val signature1 = module.sign(dataToSign, alias, signaturePrompt)
        val signature2 = module.sign(dataToSign, alias, signaturePrompt)

        assertNotEquals(
            "Multiple RSA signatures should be equal", signature1, signature2
        )
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testEcKeyVerify() = runTest {
        module.generateKeys(ec256KeySpec)
        val signature = module.sign(dataToSign, alias, signaturePrompt)
        val verified = module.verify(dataToSign, signature, alias)

        assertTrue("Cannot verify EC signed data", verified)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun testRsaKeyVerify() = runTest {
        module.generateKeys(rsa2048KeySpec)
        val signature = module.sign(dataToSign, alias, signaturePrompt)
        val verified = module.verify(dataToSign, signature, alias)

        assertTrue("Cannot verify RSA signed data", verified)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class, EitherType::class)
    fun testExternalEcKeyVerify() = runTest {
        val publicKey = module.generateKeys(ec256KeySpec)
        val signature = module.sign(dataToSign, alias, signaturePrompt)
        module.deleteKey(alias)
        val either = mockEitherFirstType<ECPublicKey, RSAPublicKey>(publicKey as ECPublicKey)

        val verified = module.verifyWithKey(
            dataToSign, signature, either
        )

        assertTrue("Cannot verify data signed with external EC key", verified)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class, EitherType::class)
    fun testExternalRsaKeyVerify() = runTest {
        val publicKey = module.generateKeys(rsa2048KeySpec)
        val signature = module.sign(dataToSign, alias, signaturePrompt)
        module.deleteKey(alias)
        val either = mockEitherSecondType<ECPublicKey, RSAPublicKey>(publicKey as RSAPublicKey)

        val verified = module.verifyWithKey(
            dataToSign, signature, either
        )

        assertTrue("Cannot verify data signed with external RSA key", verified)
    }

}
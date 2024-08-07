package expo.module.signature

import expo.module.signature.models.ECPublicKey
import expo.module.signature.models.KeySpec
import expo.module.signature.models.RSAPublicKey
import expo.module.signature.models.SignatureAlgorithm
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

class SignatureModuleTest {
    private val alias = "TestKeyAlias"
    private val dataToSign = "Test Data To Sign"

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

    companion object {
        @JvmStatic
        lateinit var module: SignatureModule

        @JvmStatic
        @BeforeClass
        fun setup(): Unit {
            module = SignatureModule()
        }
    }

    @After
    fun tearDown() {
        module.deleteKey(alias)
    }

    @Test()
    fun testEcKeysGenerationType() {
        val publicKey = module.generateKeys(ec256KeySpec)

        assertTrue("Generated key type is not EC", publicKey is ECPublicKey)
    }

    @Test()
    fun testRsaKeysGenerationType() {
        val publicKey = module.generateKeys(rsa2048KeySpec)

        assertTrue("Generated key type is not RSA", publicKey is RSAPublicKey)
    }

    @Test()
    fun testNoKeyRetrieval() {
        val publicKey = module.getPublicKey(alias)

        assertNull("Unknow key retrieved from keychain", publicKey)
    }

    @Test()
    fun testEcPublicKeyRetrieval() {
        module.generateKeys(ec256KeySpec)
        val publicKey = module.getPublicKey(alias)

        assertNotNull("Can't retrieve EC public key", publicKey)
        assertTrue("Retrieved key type is not EC", publicKey is ECPublicKey)
    }

    @Test()
    fun testRsaPublicKeyRetrieval() {
        module.generateKeys(rsa2048KeySpec)
        val publicKey = module.getPublicKey(alias)

        assertNotNull("Can't retrieve RSA public key", publicKey)
        assertTrue("Retrieved key type is not RSA", publicKey is RSAPublicKey)
    }

}
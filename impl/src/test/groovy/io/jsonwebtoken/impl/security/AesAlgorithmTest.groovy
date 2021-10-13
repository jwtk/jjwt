package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*
import org.junit.Test

import java.security.SecureRandom

import static org.junit.Assert.assertSame
import static org.junit.Assert.fail

/**
 * @since JJWT_RELEASE_VERSION
 */
class AesAlgorithmTest {

    @Test(expected = IllegalArgumentException)
    void testConstructorWithoutRequiredKeyLength() {
        new TestAesAlgorithm('foo', 'foo', 0)
    }

    @Test
    void testAssertKeyLength() {

        def alg = new TestAesAlgorithm('foo', 'foo', 192)

        def key = EncryptionAlgorithms.A128GCM.generateKey() //weaker than required

        def request = new DefaultCryptoRequest(null, null, new byte[1], key)

        try {
            alg.assertKey(request)
            fail()
        } catch (SecurityException expected) {
        }
    }

    @Test
    void testGetSecureRandomWhenRequestHasSpecifiedASecureRandom() {

        def alg = new TestAesAlgorithm('foo', 'foo', 128)

        def secureRandom = new SecureRandom()

        def req = new DefaultAeadRequest(null, secureRandom, 'data'.getBytes(), alg.generateKey(), 'aad'.getBytes())

        def returnedSecureRandom = alg.ensureSecureRandom(req)

        assertSame(secureRandom, returnedSecureRandom)
    }

    static class TestAesAlgorithm extends AesAlgorithm implements AeadAlgorithm {

        TestAesAlgorithm(String name, String transformationString, int requiredKeyLengthInBits) {
            super(name, transformationString, requiredKeyLengthInBits)
        }

        @Override
        AeadResult encrypt(AeadRequest symmetricAeadRequest) {
            return null
        }

        @Override
        PayloadSupplier<byte[]> decrypt(DecryptAeadRequest symmetricAeadDecryptionRequest) {
            return null
        }
    }

}

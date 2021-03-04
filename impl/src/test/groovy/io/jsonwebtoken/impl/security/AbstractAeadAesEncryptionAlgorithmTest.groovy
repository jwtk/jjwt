package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class AbstractAeadAesEncryptionAlgorithmTest {

    @Test(expected = IllegalArgumentException)
    void testConstructorWithIvLargerThanAesBlockSize() {
        new TestAesAeadAlgorithm('foo', 'foo', 136, 128)
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithoutIvLength() {
        new TestAesAeadAlgorithm('foo', 'foo', 0, 128)
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithoutRequiredKeyLength() {
        new TestAesAeadAlgorithm('foo', 'foo', 128, 0)
    }

    @Test
    void testDoEncryptFailure() {

        def alg = new TestAesAeadAlgorithm('foo', 'foo', 128, 128) {
            @Override
            protected SymmetricAeadEncryptionResult doEncrypt(SymmetricAeadRequest symmetricAeadRequest) throws Exception {
                throw new IllegalArgumentException('broken')
            }
        }

        def req = new DefaultSymmetricAeadRequest('bar'.getBytes(), alg.generateKey(), 'foo'.getBytes());

        try {
            alg.encrypt(req)
        } catch (CryptoException expected) {
            assertTrue expected.getCause() instanceof IllegalArgumentException
            assertTrue expected.getCause().getMessage().equals('broken')
        }
    }

    @Test
    void testAssertKeyLength() {

        def requiredKeyLength = 16

        def alg = new TestAesAeadAlgorithm('foo', 'foo', 128, requiredKeyLength)

        byte[] bytes = new byte[requiredKeyLength + 1] //not same as requiredKeyByteLength, but it should be
        Randoms.secureRandom().nextBytes(bytes)

        try {
            alg.assertKeyLength(new SecretKeySpec(bytes, "AES"))
            fail()
        } catch (CryptoException expected) {
        }
    }

    @Test
    void testGetSecureRandomWhenRequestHasSpecifiedASecureRandom() {

        def alg = new TestAesAeadAlgorithm('foo', 'foo', 128, 128)

        def secureRandom = new SecureRandom()

        def req = new DefaultSymmetricAeadRequest(null, secureRandom, 'data'.getBytes(), alg.generateKey(), 'aad'.getBytes())

        def returnedSecureRandom = alg.ensureSecureRandom(req)

        assertSame(secureRandom, returnedSecureRandom)
    }

    static class TestAesAeadAlgorithm extends AesAeadAlgorithm {

        TestAesAeadAlgorithm(String name, String transformationString, int generatedIvLengthInBits, int requiredKeyLengthInBits) {
            super(name, transformationString, generatedIvLengthInBits, requiredKeyLengthInBits)
        }

        @Override
        protected SymmetricAeadEncryptionResult doEncrypt(SymmetricAeadRequest symmetricAeadRequest) throws Exception {
            return null
        }

        @Override
        protected byte[] doDecrypt(SymmetricAeadDecryptionRequest symmetricAeadDecryptionRequest) throws Exception {
            return new byte[0]
        }
    }

}

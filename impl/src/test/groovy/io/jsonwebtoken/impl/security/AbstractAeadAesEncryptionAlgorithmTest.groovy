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
        new TestAesEncryptionAlgorithm('foo', 'foo', 136, 128)
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithoutIvLength() {
        new TestAesEncryptionAlgorithm('foo', 'foo', 0, 128)
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithoutRequiredKeyLength() {
        new TestAesEncryptionAlgorithm('foo', 'foo', 128, 0)
    }

    @Test
    void testDoEncryptFailure() {

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, 128) {
            @Override
            protected AeadIvEncryptionResult doEncrypt(AeadRequest<byte[], SecretKey> req) throws Exception {
                throw new IllegalArgumentException('broken')
            }
        }

        def req = new DefaultAesEncryptionRequest<>('bar'.getBytes(), alg.generateKey(), 'foo'.getBytes());

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

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, requiredKeyLength)

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

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, 128)

        def secureRandom = new SecureRandom()

        def req = new DefaultAesEncryptionRequest('data'.getBytes(), alg.generateKey(), null, secureRandom, 'aad'.getBytes())

        def returnedSecureRandom = alg.ensureSecureRandom(req)

        assertSame(secureRandom, returnedSecureRandom)
    }

    @Test(expected = CryptoException)
    void testDoGenerateKeyException() {
        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, 128) {
            @Override
            protected SecretKey doGenerateKey() throws Exception {
                throw new IllegalStateException("testmsg")
            }
        }
        alg.generateKey()
    }

    static class TestAesEncryptionAlgorithm extends AbstractAeadAesEncryptionAlgorithm {

        TestAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLengthInBits, int requiredKeyLengthInBits) {
            super(name, transformationString, generatedIvLengthInBits, requiredKeyLengthInBits)
        }

        @Override
        protected AeadIvEncryptionResult doEncrypt(AeadRequest<byte[], SecretKey> secretKeyAeadRequest) throws Exception {
            return null
        }

        @Override
        protected byte[] doDecrypt(AeadIvRequest<byte[], SecretKey> secretKeyAeadIvDecryptionRequest) throws Exception {
            return new byte[0]
        }
    }

}

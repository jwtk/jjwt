package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.AeadIvEncryptionResult
import io.jsonwebtoken.security.CryptoException
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertEquals

/**
 * @since JJWT_RELEASE_VERSION
 */
class HmacAesEncryptionAlgorithmTest {

    @Test(expected = SignatureException)
    void testDecryptWithInvalidTag() {

        def alg = EncryptionAlgorithms.A128CBC_HS256;

        SecretKey key = alg.generateKey()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def req = new DefaultEncryptionRequest(plaintext, key, null, null, null, null)
        def result = alg.encrypt(req);
        assert result instanceof AeadIvEncryptionResult

        def realTag = result.getAuthenticationTag();

        //fake it:
        def fakeTag = new byte[realTag.length]
        Randoms.secureRandom().nextBytes(fakeTag)

        def dreq = new DefaultAeadIvRequest(result.getCiphertext(), key, null, null, result.getInitializationVector(), null, fakeTag)
        alg.decrypt(dreq)
    }

    @Test(expected = CryptoException)
    void testGenerateKeyWithWeakSigAlgKey() {
        final byte[] bytes = new byte[24] // less than 32 bytes/256 bits
        Randoms.secureRandom().nextBytes(bytes)

        def sigAlg = new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256) {
            @Override
            SecretKey generateKey() {
                return new SecretKeySpec(bytes, 'HmacSHA256')
            }
        }
        def alg = new HmacAesEncryptionAlgorithm("A128CBC-HS256", sigAlg)
        alg.generateKey()
    }

    @Test
    void testGenerateKeyWithLongerThanExpectedSigAlgKey() {
        final byte[] macKeyBytes = new byte[64] // more than required 32 bytes / 256 bits
        Randoms.secureRandom().nextBytes(macKeyBytes)

        def sigAlg = new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256) {
            @Override
            SecretKey generateKey() {
                return new SecretKeySpec(macKeyBytes, 'HmacSHA256')
            }
        }
        def alg = new HmacAesEncryptionAlgorithm("A128CBC-HS256", sigAlg)
        def key = alg.generateKey()

        def encryptionKeyBytes = key.getEncoded()

        assertEquals 512, encryptionKeyBytes.length * Byte.SIZE

        //per https://tools.ietf.org/html/rfc7518#section-5.2.2.1 ensure the first half of the generated encryption
        // key is the first 32 bytes of the larger-than-expected mac key
        byte[] macKeyFirst32Bytes = new byte[32]
        byte[] encKeyFirst32Bytes = new byte[32]
        System.arraycopy(macKeyBytes, 0, macKeyFirst32Bytes, 0, 32)
        System.arraycopy(encryptionKeyBytes, 0, encKeyFirst32Bytes, 0, 32)
        assert Arrays.equals(macKeyFirst32Bytes, encKeyFirst32Bytes)
    }
}

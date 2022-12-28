package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.security.AeadAlgorithm
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals

/**
 * @since JJWT_RELEASE_VERSION
 */
class HmacAesAeadAlgorithmTest {

    @Test
    void testKeyBitLength() {
        // asserts that key lengths are double than what is usually expected for AES
        // due to the encrypt-then-mac scheme requiring two separate keys
        // (encrypt key is half of the generated key, mac key is the 2nd half of the generated key):
        assertEquals 256, EncryptionAlgorithms.A128CBC_HS256.getKeyBitLength()
        assertEquals 384, EncryptionAlgorithms.A192CBC_HS384.getKeyBitLength()
        assertEquals 512, EncryptionAlgorithms.A256CBC_HS512.getKeyBitLength()
    }

    @Test
    void testGenerateKey() {
        def algs = [
                EncryptionAlgorithms.A128CBC_HS256,
                EncryptionAlgorithms.A192CBC_HS384,
                EncryptionAlgorithms.A256CBC_HS512
        ]
        for(AeadAlgorithm alg : algs) {
            SecretKey key = alg.keyBuilder().build()
            assertEquals alg.getKeyBitLength(), Bytes.bitLength(key.getEncoded())
        }
    }

    @Test(expected = SignatureException)
    void testDecryptWithInvalidTag() {

        def alg = EncryptionAlgorithms.A128CBC_HS256;

        SecretKey key = alg.keyBuilder().build()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def req = new DefaultAeadRequest(plaintext, null, null, key, null)
        def result = alg.encrypt(req);

        def realTag = result.getDigest();

        //fake it:
        def fakeTag = new byte[realTag.length]
        Randoms.secureRandom().nextBytes(fakeTag)

        def dreq = new DefaultAeadResult(null, null, result.getPayload(), key, null, fakeTag, result.getInitializationVector())
        alg.decrypt(dreq)
    }
}

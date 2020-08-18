package io.jsonwebtoken.impl.security

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
    void testGenerateKey() {
        def alg = EncryptionAlgorithms.A128CBC_HS256
        SecretKey key = alg.generateKey();
        int algKeyByteLength = (alg.keyBitLength * 2) / Byte.SIZE
        assertEquals algKeyByteLength, key.getEncoded().length
    }

    @Test(expected = SignatureException)
    void testDecryptWithInvalidTag() {

        def alg = EncryptionAlgorithms.A128CBC_HS256;

        SecretKey key = alg.generateKey()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def req = new DefaultAeadRequest(null, null, plaintext, key, null)
        def result = alg.encrypt(req);

        def realTag = result.getDigest();

        //fake it:
        def fakeTag = new byte[realTag.length]
        Randoms.secureRandom().nextBytes(fakeTag)

        def dreq = new DefaultAeadResult(null, null, result.getPayload(), key, null, fakeTag, result.getInitializationVector())
        alg.decrypt(dreq)
    }
}

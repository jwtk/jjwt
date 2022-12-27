package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.KeyAlgorithms
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.SecretKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertEquals

class DefaultRsaKeyAlgorithmTest {

    static final algs = [KeyAlgorithms.RSA1_5, KeyAlgorithms.RSA_OAEP, KeyAlgorithms.RSA_OAEP_256] as List<DefaultRsaKeyAlgorithm>

    @Test
    void testValidateNonRSAKey() {
        SecretKey key = KeyAlgorithms.A128KW.keyBuilder().build()
        for (DefaultRsaKeyAlgorithm alg : algs) {
            // if RSAKey interface isn't exposed (e.g. PKCS11 or HSM), don't error:
            alg.validate(key, true)
            alg.validate(key, false)
        }
    }

    @Test
    void testWeakEncryptionKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPublicKey key = createMock(RSAPublicKey)
            expect(key.getModulus()).andReturn(BigInteger.ONE)
            replay(key)
            try {
                alg.validate(key, true)
            } catch (WeakKeyException e) {
                String id = alg.getId()
                String section = id.equals("RSA1_5") ? "4.2" : "4.3"
                String msg = "The RSA encryption key's size (modulus) is 1 bits which is not secure enough for " +
                        "the $id algorithm. The JWT JWA Specification (RFC 7518, Section $section) states that " +
                        "RSA keys MUST have a size >= 2048 bits. " +
                        "See https://www.rfc-editor.org/rfc/rfc7518.html#section-$section for more information."
                assertEquals(msg, e.getMessage())
            }
            verify(key)
        }
    }

    @Test
    void testWeakDecryptionKey() {
        for (DefaultRsaKeyAlgorithm alg : algs) {
            RSAPrivateKey key = createMock(RSAPrivateKey)
            expect(key.getModulus()).andReturn(BigInteger.ONE)
            replay(key)
            try {
                alg.validate(key, false)
            } catch (WeakKeyException e) {
                String id = alg.getId()
                String section = id.equals("RSA1_5") ? "4.2" : "4.3"
                String msg = "The RSA decryption key's size (modulus) is 1 bits which is not secure enough for " +
                        "the $id algorithm. The JWT JWA Specification (RFC 7518, Section $section) states that " +
                        "RSA keys MUST have a size >= 2048 bits. " +
                        "See https://www.rfc-editor.org/rfc/rfc7518.html#section-$section for more information."
                assertEquals(msg, e.getMessage())
            }
            verify(key)
        }
    }
}

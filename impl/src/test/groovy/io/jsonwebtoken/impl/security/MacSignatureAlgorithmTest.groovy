package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SecurityException
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertEquals

class MacSignatureAlgorithmTest {

    static MacSignatureAlgorithm newAlg() {
        return new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256)
    }

    @Test(expected = SecurityException)
    void testKeyGeneratorNoSuchAlgorithm() {
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('HS256', 'foo', 256);
        alg.keyBuilder().build()
    }

    @Test
    void testKeyGeneratorKeyLength() {
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256);
        assertEquals 256, alg.keyBuilder().build().getEncoded().length * Byte.SIZE

        alg = new MacSignatureAlgorithm('A128CBC-HS256', 'HmacSHA256', 128)
        assertEquals 128, alg.keyBuilder().build().getEncoded().length * Byte.SIZE
    }

    @Test(expected = IllegalArgumentException)
    void testValidateNullKey() {
        newAlg().validateKey(null, true)
    }

    @Test(expected = InvalidKeyException)
    void testValidateKeyNoAlgorithm() {
        newAlg().validateKey(new SecretKeySpec(new byte[1], ' '), true)
    }

    @Test(expected = InvalidKeyException)
    void testValidateKeyInvalidJcaAlgorithm() {
        newAlg().validateKey(new SecretKeySpec(new byte[1], 'foo'), true)
    }

    @Test
    void testValidateKeyEncodedNotAvailable() {
        def key = new SecretKeySpec(new byte[1], 'HmacSHA256') {
            @Override
            byte[] getEncoded() {
                throw new UnsupportedOperationException("HSM: not allowed")
            }
        }
        newAlg().validateKey(key, true)
    }

    @Test
    void testValidateKeyStandardAlgorithmWeakKey() {
        byte[] bytes = new byte[24]
        Randoms.secureRandom().nextBytes(bytes)
        try {
            newAlg().validateKey(new SecretKeySpec(bytes, 'HmacSHA256'), true)
        } catch (WeakKeyException expected) {
            String msg = 'The signing key\'s size is 192 bits which is not secure enough for the HS256 algorithm. ' +
                    'The JWT JWA Specification (RFC 7518, Section 3.2) states that keys used with HS256 MUST have a ' +
                    'size >= 256 bits (the key size must be greater than or equal to the hash output size). ' +
                    'Consider using the SignatureAlgorithms.HS256.generateKey() method to create a key guaranteed ' +
                    'to be secure enough for HS256.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more ' +
                    'information.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testValidateKeyCustomAlgorithmWeakKey() {
        byte[] bytes = new byte[24]
        Randoms.secureRandom().nextBytes(bytes)
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('foo', 'foo', 256);
        try {
            alg.validateKey(new SecretKeySpec(bytes, 'HmacSHA256'), true)
        } catch (WeakKeyException expected) {
            assertEquals 'The signing key\'s size is 192 bits which is not secure enough for the foo algorithm. The foo algorithm requires keys to have a size >= 256 bits.', expected.getMessage()
        }
    }
}

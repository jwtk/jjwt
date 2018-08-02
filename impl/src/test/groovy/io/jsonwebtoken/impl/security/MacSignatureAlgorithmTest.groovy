package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureAlgorithm
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.Security

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertSame

class MacSignatureAlgorithmTest {

    static MacSignatureAlgorithm newAlg() {
        return new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256)
    }

    @Test(expected = UnsupportedOperationException)
    void testKeyGeneratorNoSuchAlgorithm() {
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('HS256', 'foo', 256);
        alg.generateKey()
    }

    @Test
    void testDoGetMacInstanceWithProvider() {
        Provider provider = Security.getProvider("SunJCE")
        MacSignatureAlgorithm alg = newAlg()
        assertNotNull alg.doGetMacInstance('HmacSHA256', provider)
    }

    @Test
    void testGetMacInstanceDefault() {
        def expected = new NoSuchAlgorithmException('test')
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256) {
            @Override
            def Mac doGetMacInstance(String jcaName, Provider provider) throws NoSuchAlgorithmException {
                throw expected
            }
        }
        try {
            alg.sign(new DefaultCryptoRequest<byte[], Key>(new byte[1], new SecretKeySpec(new byte[32], 'HmacSHA256'), null, null))
        } catch (SignatureException e) {
            assertEquals 'There is no JCA Provider available that supports MAC algorithm name \'HmacSHA256\'.', e.getMessage()
        }
    }

    @Test
    void testGetMacInstanceWithProvider() {
        Provider provider = createMock(Provider)
        String providerString = provider.toString()
        def expected = new NoSuchAlgorithmException('test')
        MacSignatureAlgorithm alg = new MacSignatureAlgorithm('HS256', 'HmacSHA256', 256) {
            @Override
            def Mac doGetMacInstance(String jcaName, Provider p) throws NoSuchAlgorithmException {
                throw expected
            }
        }
        try {
            alg.sign(new DefaultCryptoRequest<byte[], Key>(new byte[1], new SecretKeySpec(new byte[32], 'HmacSHA256'), provider, null))
        } catch (SignatureException e) {
            assertEquals 'The specified JCA Provider {' + providerString + '} does not support MAC algorithm name \'HmacSHA256\'.', e.getMessage()
        }
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

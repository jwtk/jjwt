package io.jsonwebtoken.impl.security

import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class ConstantKeyLocatorTest {

    @Test
    void testSignatureVerificationKey() {
        def key = new SecretKeySpec(new byte[1], 'AES') //dummy key for testing
        assertSame key, new ConstantKeyLocator(key, null).resolveKey(new DefaultJwsHeader())
    }

    @Test
    void testSignatureVerificationKeyMissing() {
        def resolver = new ConstantKeyLocator(null, null)
        try {
            resolver.resolveKey(new DefaultJwsHeader())
        } catch (UnsupportedJwtException uje) {
            String msg = 'Signed JWTs are not supported: the JwtParser has not been configured with a signature ' +
                    'verification key or a KeyResolver. Consider configuring the JwtParserBuilder with one of these ' +
                    'to ensure it can use the necessary key to verify JWS signatures.'
            assertEquals msg, uje.getMessage()
        }
    }

    @Test
    void testDecryptionKey() {
        def key = new SecretKeySpec(new byte[1], 'AES') //dummy key for testing
        assertSame key, new ConstantKeyLocator(null, key).resolveKey(new DefaultJweHeader())
    }

    @Test
    void testDecryptionKeyMissing() {
        def resolver = new ConstantKeyLocator(null, null)
        try {
            resolver.resolveKey(new DefaultJweHeader())
        } catch (UnsupportedJwtException uje) {
            String msg = 'Encrypted JWTs are not supported: the JwtParser has not been configured with a decryption ' +
                    'key or a KeyResolver. Consider configuring the JwtParserBuilder with one of these ' +
                    'to ensure it can use the necessary key to decrypt JWEs.'
            assertEquals msg, uje.getMessage()
        }
    }
}

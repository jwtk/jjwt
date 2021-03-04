package io.jsonwebtoken.impl.security

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Before
import org.junit.Test
import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultEncryptionAlgorithmLocatorTest {

    private DefaultEncryptionAlgorithmLocator locator

    @Before
    void setUp() {
        locator = new DefaultEncryptionAlgorithmLocator()
    }

    private static JweHeader header(String enc) {
        return Jwts.jweHeader().setEncryptionAlgorithm(enc)
    }

    @Test
    void testA128CBCHS256() {
        assertSame EncryptionAlgorithms.A128CBC_HS256, locator.getEncryptionAlgorithm(header('A128CBC-HS256'))
    }

    @Test
    void testA192CBCHS384() {
        assertSame EncryptionAlgorithms.A192CBC_HS384, locator.getEncryptionAlgorithm(header('A192CBC-HS384'))
    }

    @Test
    void testA256CBCHS512() {
        assertSame EncryptionAlgorithms.A256CBC_HS512, locator.getEncryptionAlgorithm(header('A256CBC-HS512'))
    }

    @Test
    void testA128GCM() {
        assertSame EncryptionAlgorithms.A128GCM, locator.getEncryptionAlgorithm(header('A128GCM'))
    }

    @Test
    void testA192GCM() {
        assertSame EncryptionAlgorithms.A192GCM, locator.getEncryptionAlgorithm(header('A192GCM'))
    }

    @Test
    void testA256GCM() {
        assertSame EncryptionAlgorithms.A256GCM, locator.getEncryptionAlgorithm(header('A256GCM'))
    }

    @Test
    void testMissingEncAlg() {
        try {
            locator.getEncryptionAlgorithm(Jwts.jweHeader())
            fail()
        } catch (MalformedJwtException expected) {
        }
    }

    @Test
    void testNullEncAlg() {
        try {
            locator.getEncryptionAlgorithm(header(null))
            fail()
        } catch (MalformedJwtException expected) {
        }
    }

    @Test
    void testEmptyEncAlg() {
        try {
            locator.getEncryptionAlgorithm(header('  '))
            fail()
        } catch (MalformedJwtException expected) {
        }
    }

    @Test
    void testUnknownEncAlg() {
        try {
            locator.getEncryptionAlgorithm(header('foo'))
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals "JWE 'enc' header parameter value of 'foo' does not match a JWE standard algorithm " +
                    "identifier.  If 'foo' represents a custom algorithm, the JwtParser must be configured " +
                    "with a custom EncryptionAlgorithmLocator instance that knows how to return a compatible " +
                    "EncryptionAlgorithm instance.  Otherwise, this JWE is invalid and may not be used safely.", e.message
        }
    }

}

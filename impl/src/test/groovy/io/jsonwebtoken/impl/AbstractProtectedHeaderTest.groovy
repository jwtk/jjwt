package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.SecretJwk
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class AbstractProtectedHeaderTest {

    private AbstractProtectedHeader header

    @Before
    void setUp() {
        header = new DefaultJwsHeader() // extends AbstractProtectedHeader
    }

    @Test
    void testJku() {
        URI uri = URI.create('https://google.com')
        header.put('jku', uri)
        assertEquals uri.toString(), header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testJkuString() { //test canonical/idiomatic conversion
        String url = 'https://google.com'
        URI uri = URI.create(url)
        header.put('jku', url)
        assertEquals url, header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testX509Url() {
        URI uri = URI.create('https://google.com')
        header.setX509Url(uri)
        assertEquals uri, header.getX509Url()
    }

    @Test
    void testX509UrlString() { //test canonical/idiomatic conversion
        String url = 'https://google.com'
        URI uri = URI.create(url)
        header.put('x5u', url)
        assertEquals url, header.get('x5u')
        assertEquals uri, header.getX509Url()
    }

    @Test
    void testJwkWithNull() {
        header.put('jwk', null)
        assertNull header.getJwk()
    }

    @Test
    void testJwkWithEmptyMap() {
        header.put('jwk', [:])
        assertNull header.getJwk()
    }

    @Test
    void testJwkWithoutMap() {
        try {
            header.put('jwk', 42)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWS header 'jwk' (JSON Web Key) value: 42. Cause: Unsupported value type - " +
                    "expected a Map or Jwk instance.  Type found: java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithJwk() {
        EcPrivateJwk jwk = Jwks.builder().forEcKeyPair(TestKeys.ES256.pair).build()
        EcPublicJwk pubJwk = jwk.toPublicJwk()
        header.setJwk(pubJwk)
        assertEquals pubJwk, header.getJwk()
    }

    @Test
    void testJwkWithMap() {
        EcPrivateJwk jwk = Jwks.builder().forEcKeyPair(TestKeys.ES256.pair).build()
        EcPublicJwk pubJwk = jwk.toPublicJwk()
        Map<String, ?> m = new LinkedHashMap<>(pubJwk)
        header.put('jwk', m)
        assertEquals pubJwk, header.getJwk()
    }

    @Test
    void testJwkWithBadMapKeys() {
        def m = [42: "hello"]
        try {
            header.put('jwk', m)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWS header 'jwk' (JSON Web Key) value: {42=hello}. Cause: Unsupported 'jwk' map " +
                    "value - all JWK map keys must be Strings.  Encountered key '42' of type java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithSecretJwk() {
        SecretJwk jwk = Jwks.builder().forKey(TestKeys.HS256).build()
        try {
            header.put('jwk', jwk)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWS header 'jwk' (JSON Web Key) value: {kty=oct, k=<redacted>}. Cause: " +
                    "Unsupported JWK map - JWK values must represent a PublicJwk, not a SecretJwk."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithPrivateJwk() {
        EcPrivateJwk jwk = Jwks.builder().forEcKeyPair(TestKeys.ES256.pair).build()
        try {
            header.put('jwk', jwk)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWS header 'jwk' (JSON Web Key) value: {kty=EC, crv=P-256, " +
                    "x=xNKMMIsawShLG4LYxpNP0gqdgK_K69UXCLt3AE3zp-Q, y=_vzQymVtA7RHRTfBWZo75mxPgDkE8g7bdHI3siSuJOk, " +
                    "d=<redacted>}. Cause: Unsupported JWK map - JWK values must represent a PublicJwk, " +
                    "not a PrivateJwk."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testCritNull() {
        header.put('crit', null)
        assertNull header.getCritical()
    }

    @Test
    void testCritEmpty() {
        header.put('crit', [])
        assertNull header.getCritical()
    }

    @Test
    void testCritSingleValue() {
        header.put('crit', 'foo')
        assertEquals(["foo"] as Set, header.get('crit'))
        assertEquals(["foo"] as Set, header.getCritical())
    }

    @Test
    void testCritArray() {
        String[] crit = ["exp"] as String[]
        header.put('crit', crit)
        assertEquals(["exp"] as Set, header.get('crit'))
        assertEquals(["exp"] as Set, header.getCritical())
    }

    @Test
    void testCritList() {
        List<String> crit = ["exp"] as List<String>
        header.put('crit', crit)
        assertEquals(["exp"] as Set, header.get('crit'))
        assertEquals(["exp"] as Set, header.getCritical())
    }
}

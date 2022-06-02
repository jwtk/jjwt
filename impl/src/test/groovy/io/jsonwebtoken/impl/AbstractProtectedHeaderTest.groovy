package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Collections
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
        header = new AbstractProtectedHeader(AbstractProtectedHeader.FIELDS) {}
    }

    @Test
    void testKeyId() {
        def kid = 'foo'
        header.setKeyId(kid)
        assertEquals kid, header.get('kid')
        assertEquals kid, header.getKeyId()
    }

    @Test
    void testKeyIdNonString() {
        try {
            header.put('kid', 42)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'kid' (Key ID) value: 42. Unsupported value type. " +
                    "Expected: java.lang.String, found: java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testSetJku() {
        URI uri = URI.create('https://github.com')
        header.setJwkSetUrl(uri)
        assertEquals uri.toString(), header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testPutJkuUri() {
        URI uri = URI.create('https://google.com')
        header.put('jku', uri)
        assertEquals uri.toString(), header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testPutJkuString() {
        String url = 'https://google.com'
        URI uri = URI.create(url)
        header.put('jku', url)
        assertEquals url, header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testPutJkuNonString() {
        try {
            header.put('jku', 42)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'jku' (JWK Set URL) value: 42. Values must be either String or " +
                    "java.net.URI instances. Value type found: java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
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
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: 42. " +
                    "Value must be a Jwk<?> or Map<String,?>. Type found: java.lang.Integer."
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
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {42=hello}. JWK map keys must be Strings. " +
                    "Encountered key '42' of type java.lang.Integer."
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
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {kty=oct, k=<redacted>}. " +
                    "Value must be a Public JWK, not a Secret JWK."
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
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {kty=EC, crv=P-256, " +
                    "x=xNKMMIsawShLG4LYxpNP0gqdgK_K69UXCLt3AE3zp-Q, y=_vzQymVtA7RHRTfBWZo75mxPgDkE8g7bdHI3siSuJOk, " +
                    "d=<redacted>}. Value must be a Public JWK, not an EC Private JWK."
            assertEquals msg, expected.getMessage()
        }
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
    void testX509CertChain() {
        def bundle = TestKeys.RS256
        List<String> encodedCerts = Collections.of(Encoders.BASE64.encode(bundle.cert.getEncoded()))
        header.setX509CertificateChain(bundle.chain)
        assertEquals bundle.chain, header.getX509CertificateChain()
        assertEquals encodedCerts, header.get('x5c')
    }

    @Test
    void testX509CertSha1Thumbprint() {
        byte[] thumbprint = new byte[16] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        header.setX509CertificateSha1Thumbprint(thumbprint)
        assertArrayEquals thumbprint, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testX509CertSha256Thumbprint() {
        byte[] thumbprint = new byte[32] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        header.setX509CertificateSha256Thumbprint(thumbprint)
        assertArrayEquals thumbprint, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testCritical() {
        Set<String> crits = Collections.setOf('foo', 'bar')
        header.setCritical(crits)
        assertEquals crits, header.getCritical()
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

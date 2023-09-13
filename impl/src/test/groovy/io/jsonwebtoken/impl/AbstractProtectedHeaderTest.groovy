/*
 * Copyright (C) 2022 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import static org.junit.Assert.*

class AbstractProtectedHeaderTest {

    private static DefaultProtectedHeader h(Map<String, ?> m) {
        return new DefaultProtectedHeader(DefaultProtectedHeader.PARAMS, m)
    }

    @Test
    void testKeyId() {
        def kid = 'foo'
        def header = h([kid: kid])
        assertEquals kid, header.get('kid')
        assertEquals kid, header.getKeyId()
    }

    @Test
    void testKeyIdNonString() {
        try {
            h([kid: 42])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'kid' (Key ID) value: 42. Unsupported value type. " +
                    "Expected: java.lang.String, found: java.lang.Integer"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJku() {
        URI uri = URI.create('https://github.com')
        def header = Jwts.header().jwkSetUrl(uri).build() as DefaultProtectedHeader
        assertEquals uri.toString(), header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testJkuString() {
        String url = 'https://google.com'
        URI uri = URI.create(url)
        def header = h([jku: url])
        assertEquals url, header.get('jku')
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testJkuNonString() {
        try {
            h([jku: 42])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'jku' (JWK Set URL) value: 42. Values must be either String or " +
                    "java.net.URI instances. Value type found: java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkNull() {
        def header = h([jwk: null])
        assertNull header.getJwk()
    }

    @Test
    void testJwkWithEmptyMap() {
        def header = h([jwk: [:]])
        assertNull header.getJwk()
    }

    @Test
    void testJwkWithoutMap() {
        try {
            h([jwk: 42])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header ${DefaultProtectedHeader.JWK} value: 42. " +
                    "JWK must be a Map<String,?> (JSON Object). Type found: java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithJwk() {
        EcPrivateJwk jwk = Jwks.builder().ecKeyPair(TestKeys.ES256.pair).build()
        EcPublicJwk pubJwk = jwk.toPublicJwk()
        def header = h([jwk: pubJwk])
        assertEquals pubJwk, header.getJwk()
    }

    @Test
    void testJwkWithMap() {
        EcPrivateJwk jwk = Jwks.builder().ecKeyPair(TestKeys.ES256.pair).build()
        EcPublicJwk pubJwk = jwk.toPublicJwk()
        Map<String, ?> m = new LinkedHashMap<>(pubJwk)
        def header = h([jwk: m])
        assertEquals pubJwk, header.getJwk()
    }

    @Test
    void testJwkWithBadMapKeys() {
        def m = [kty: 'oct', 42: "hello"]
        try {
            h([jwk: m])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {kty=oct, 42=hello}. JWK map keys " +
                    "must be Strings. Encountered key '42' of type java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithSecretJwk() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).build()
        try {
            h([jwk: jwk])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {alg=HS256, kty=oct, k=<redacted>}. " +
                    "Value must be a Public JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testJwkWithPrivateJwk() {
        EcPrivateJwk jwk = Jwks.builder().ecKeyPair(TestKeys.ES256.pair).build()
        try {
            h([jwk: jwk])
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWT header 'jwk' (JSON Web Key) value: {kty=EC, crv=P-256, " +
                    "x=ZWF7HQuzPoW_HarfomiU-HCMELJ486IzskTXL5fwuy4, y=Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU, " +
                    "d=<redacted>}. Value must be a Public JWK, not an EC Private JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testX509Url() {
        URI uri = URI.create('https://google.com')
        def header = h([x5u: uri])
        assertEquals uri.toString(), header.get('x5u')
        assertEquals uri, header.getX509Url()
    }

    @Test
    void testX509UrlString() { //test canonical/idiomatic conversion
        String url = 'https://google.com'
        URI uri = URI.create(url)
        def header = h([x5u: url])
        assertEquals url, header.get('x5u')
        assertEquals uri, header.getX509Url()
    }

    @Test
    void testX509CertChain() {
        def bundle = TestKeys.RS256
        List<String> encodedCerts = Collections.of(Encoders.BASE64.encode(bundle.cert.getEncoded()))
        def header = h([x5c: bundle.chain])
        assertEquals bundle.chain, header.getX509CertificateChain()
        assertEquals encodedCerts, header.get('x5c')
    }

    @Test
    void testX509CertSha1Thumbprint() {
        byte[] thumbprint = new byte[16] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        def header = h([x5t: thumbprint])
        assertArrayEquals thumbprint, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testX509CertSha256Thumbprint() {
        byte[] thumbprint = new byte[32] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        def header = h(['x5t#S256': thumbprint])
        assertArrayEquals thumbprint, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testCritical() {
        Set<String> crits = Collections.setOf('foo', 'bar')
        def header = Jwts.header().critical(crits).build() as DefaultProtectedHeader
        assertEquals crits, header.getCritical()
    }

    @Test
    void testCritNull() {
        def header = h([crit: null])
        assertNull header.getCritical()
    }

    @Test
    void testCritEmpty() {
        def header = h([crit: []])
        assertNull header.getCritical()
    }

    @Test
    void testCritSingleValue() {
        def header = h([crit: 'foo'])
        assertEquals(["foo"] as Set, header.get('crit'))
        assertEquals(["foo"] as Set, header.getCritical())
    }

    @Test
    void testCritArray() {
        String[] crit = ["exp"] as String[]
        def header = h([crit: crit])
        assertEquals(["exp"] as Set, header.get('crit'))
        assertEquals(["exp"] as Set, header.getCritical())
    }

    @Test
    void testCritList() {
        List<String> crit = ["exp"] as List<String>
        def header = h([crit: crit])
        assertEquals(["exp"] as Set, header.get('crit'))
        assertEquals(["exp"] as Set, header.getCritical())
    }
}

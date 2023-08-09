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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.RfcTests
import io.jsonwebtoken.security.HashAlgorithm
import io.jsonwebtoken.security.JwkThumbprint
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets

import static io.jsonwebtoken.impl.security.DefaultHashAlgorithm.SHA1
import static org.junit.Assert.assertEquals

class JwkThumbprintsTest {

    static final HashAlgorithm SHA256 = Jwks.HASH.@SHA256

    static byte[] digest(String json, HashAlgorithm alg) {
        def utf8Bytes = json.getBytes(StandardCharsets.UTF_8)
        def req = new DefaultRequest(utf8Bytes, null, null)
        return alg.digest(req)
    }

    static JwkThumbprint thumbprint(String json, HashAlgorithm alg) {
        return new DefaultJwkThumbprint(digest(json, alg), alg)
    }

    @Test
    void testSecretJwks() {
        TestKeys.SECRET.each { SecretKey key ->
            def jwk = Jwks.builder().key((SecretKey) key).idFromThumbprint().build()
            def json = RfcTests.stripws("""
            {"k":"${jwk.get('k').get()}","kty":"oct"}
            """)
            def s256t = thumbprint(json, SHA256)
            assertEquals s256t, jwk.thumbprint()
            assertEquals thumbprint(json, SHA1), jwk.thumbprint(SHA1)
            assertEquals s256t.toString(), jwk.getId()
        }
    }

    @Test
    void testRsaKeyPair() {
        def pair = TestKeys.RS256.pair
        def privJwk = Jwks.builder().rsaKeyPair(pair).idFromThumbprint().build()
        def pubJwk = privJwk.toPublicJwk()
        def json = RfcTests.stripws("""
        {"e":"${pubJwk.get('e')}","kty":"RSA","n":"${pubJwk.get('n')}"}
        """)

        def s256t = thumbprint(json, SHA256)

        assertEquals s256t, pubJwk.thumbprint()
        assertEquals thumbprint(json, SHA1), pubJwk.thumbprint(SHA1)
        assertEquals s256t.toString(), pubJwk.getId()

        assertEquals thumbprint(json, SHA256), privJwk.thumbprint()
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals thumbprint(json, SHA1), privJwk.thumbprint(SHA1)
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals s256t.toString(), privJwk.getId()
    }

    @Test
    void testEcKeyPair() {
        def pair = TestKeys.ES256.pair
        def privJwk = Jwks.builder().ecKeyPair(pair).idFromThumbprint().build()
        def pubJwk = privJwk.toPublicJwk()
        def json = RfcTests.stripws("""
        {"crv":"${pubJwk.get('crv')}","kty":"EC","x":"${pubJwk.get('x')}","y":"${pubJwk.get('y')}"}
        """)

        def s256t = thumbprint(json, SHA256)

        assertEquals s256t, pubJwk.thumbprint()
        assertEquals thumbprint(json, SHA1), pubJwk.thumbprint(SHA1)
        assertEquals s256t.toString(), pubJwk.getId()

        assertEquals thumbprint(json, SHA256), privJwk.thumbprint()
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals thumbprint(json, SHA1), privJwk.thumbprint(SHA1)
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals s256t.toString(), privJwk.getId()
    }

    @Test
    void testEdECKeyPair() {
        def pair = TestKeys.Ed25519.pair
        def privJwk = Jwks.builder().octetKeyPair(pair).idFromThumbprint().build()
        def pubJwk = privJwk.toPublicJwk()
        def json = RfcTests.stripws("""
        {"crv":"${pubJwk.get('crv')}","kty":"OKP","x":"${pubJwk.get('x')}"}
        """)

        def s256t = thumbprint(json, SHA256)

        assertEquals s256t, pubJwk.thumbprint()
        assertEquals thumbprint(json, SHA1), pubJwk.thumbprint(SHA1)
        assertEquals s256t.toString(), pubJwk.getId()

        assertEquals thumbprint(json, SHA256), privJwk.thumbprint()
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals thumbprint(json, SHA1), privJwk.thumbprint(SHA1)
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        assertEquals s256t.toString(), privJwk.getId()
    }
}

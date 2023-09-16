/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken

import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.DefaultJwtParser
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

/**
 * Test cases for https://datatracker.ietf.org/doc/html/rfc7797 functionality.
 */
class RFC7797Test {

    @Test
    void testJwe() {
        try {
            Jwts.builder().content('hello').encryptWith(TestKeys.A128GCM, Jwts.ENC.A128GCM)
                    .encodePayload(false) // not allowed with JWE
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for JWEs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testUnprotectedJwt() {
        try {
            Jwts.builder().content('hello')
                    .encodePayload(false) // not allowed with JWT
                    .compact()
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'Payload encoding may not be disabled for unprotected JWTs, only JWSs.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testBytesPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id)
                .build().parseContentJws(s, payload)

        assertArrayEquals payload, jws.getPayload()
    }

    @Test
    void testClaimsPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('{"sub":"me"}')

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id)
                .build().parseClaimsJws(s, payload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    @Test
    void testEmptyBytesPayload() {
        try {
            Jwts.builder().content(Bytes.EMPTY).encodePayload(false).signWith(TestKeys.HS256).compact()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "'b64' Unencoded payload option has been specified, but payload is empty."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseContentWithEmptyBytesPayload() {
        try {
            Jwts.parser().verifyWith(TestKeys.HS256).critical(DefaultJwsHeader.B64.id).build()
                    .parseContentJws('whatever', Bytes.EMPTY) // <-- empty
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'unencodedPayload argument cannot be null or empty.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseClaimsWithEmptyBytesPayload() {
        try {
            Jwts.parser().verifyWith(TestKeys.HS256).critical(DefaultJwsHeader.B64.id).build()
                    .parseClaimsJws('whatever', Bytes.EMPTY) // <-- empty
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'unencodedPayload argument cannot be null or empty.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseContentWithoutPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        // s is an unencoded-payload JWS
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()
        def expectedHeader = [alg: 'HS256', b64: false, crit: ['b64']]

        // try to parse it as a 'normal' JWS (without supplying the payload):
        try {
            Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id).build()
                    .parseContentJws(s) // <-- no payload supplied
            fail()
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            String msg = String.format(DefaultJwtParser.B64_MISSING_PAYLOAD, expectedHeader)
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseClaimsWithoutPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        // s is an unencoded-payload JWS
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def expectedHeader = [alg: 'HS256', b64: false, crit: ['b64']]

        // try to parse it as a 'normal' JWS (without supplying the payload):
        try {
            Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id).build()
                    .parseClaimsJws(s) // <-- no payload supplied
            fail()
        } catch (io.jsonwebtoken.security.SignatureException expected) {
            String msg = String.format(DefaultJwtParser.B64_MISSING_PAYLOAD, expectedHeader)
            assertEquals msg, expected.message
        }
    }

    /**
     * Asserts that, as long as a non-detached unencoded payload does not have period characters in it, it can
     * be parsed 'normally' via normal JWS signature verification logic.  It does this by using the the payload's
     * UTF-8 bytes instead of relying on a user-supplied unencodedPayload byte array.
     */
    @Test
    void testNonDetachedContent() {

        def key = TestKeys.HS256

        String payload = 'foo'

        // create a non-detached unencoded JWS:
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id).build()
                .parseContentJws(s) // <--- parse normally, without calling parseContentJws(s, unencodedPayload)

        assertArrayEquals Strings.utf8(payload), jws.getPayload()
    }

    @Test
    void testNonDetatchedClaims() {

        def key = TestKeys.HS256

        String payload = '{"sub":"me"}'

        // create a non-detached unencoded JWS:
        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical(DefaultJwsHeader.B64.id).build()
                .parseClaimsJws(s) // <--- parse normally, without calling parseClaimsJws(s, unencodedPayload)

        assertEquals 'me', jws.getPayload().getSubject()
    }


    @Test
    void testDecompression() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('hello world')

        def zip = Jwts.ZIP.DEF

        // create a detached unencoded JWS that is compressed:
        String s = Jwts.builder().content(payload).encodePayload(false)
                .compressWith(zip).signWith(key).compact()

        def jws = Jwts.parser().critical('b64').verifyWith(key).build()
                .parseContentJws(s, zip.compress(payload)) // <--- need to specify compressed unencoded payload bytes

        assertArrayEquals payload, jws.getPayload()
    }

    /**
     * Safe decompression of an unencoded payload using a SigningKeyResolver (SKR) is not possible because the SKR
     * only verifies signatures after payloads are enabled, and signatures need to be verified before the payload
     * is trusted.  And decompressing an unsecured payload is a security risk.
     */
    @Test
    void testDecompressionWhenSigningKeyResolverIsUsed() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('hello world')

        def zip = Jwts.ZIP.DEF

        // create a detached unencoded JWS that is compressed:
        String s = Jwts.builder().content(payload).encodePayload(false)
                .compressWith(zip).signWith(key).compact()

        // now try to parse a compressed unencoded using a signing key resolver:
        try {
            Jwts.parser().critical(DefaultJwsHeader.B64.id) // enable b64 extension
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        Key resolveSigningKey(JwsHeader header, byte[] content) {
                            return key
                        }
                    })
                    .build()
                    .parseContentJws(s, payload)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.B64_DECOMPRESSION_MSG, zip.id)
            assertEquals msg, expected.message
        }
    }
}

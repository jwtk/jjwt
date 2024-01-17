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
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Serializer
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
    void parseSignedContentBytes() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2

        String s = Jwts.builder().signWith(key).content(content).encodePayload(false).compact()

        // But verify with 3 types of sources: string, byte array, and two different kinds of InputStreams:
        InputStream asByteInputStream = Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedContent(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedContent(s, (InputStream) payload)
            }
            // When the supplied unencodedPayload is not a byte array or a ByteArrayInputStream, we can't know how
            // big the payload stream might be, and we don't want to pull it all into memory, so the JWS payload
            // body will be empty.  So we only assert the payload contents when we can get the bytes:
            if (payload instanceof byte[] || payload instanceof ByteArrayInputStream) {
                assertArrayEquals content, jws.getPayload()
            } else {
                assertArrayEquals Bytes.EMPTY, jws.getPayload()
            }
        }
    }

    @Test
    void parseSignedClaimsBytes() {

        def key = TestKeys.HS256

        def claims = Jwts.claims().subject('me').build()

        ByteArrayOutputStream out = new ByteArrayOutputStream()
        Services.get(Serializer).serialize(claims, out)
        byte[] content = out.toByteArray()

        String s = Jwts.builder().signWith(key).content(content).encodePayload(false).compact()

        // But verify with 3 types of sources: string, byte array, and two different kinds of InputStreams:
        InputStream asByteInputStream = Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedClaims(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedClaims(s, (InputStream) payload)
            }
            assertEquals claims, jws.getPayload()
        }
    }

    @Test
    void parseSignedContentByteArrayInputStream() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('$.02') // https://datatracker.ietf.org/doc/html/rfc7797#section-4.2
        InputStream contentStream = Streams.of(content)

        String s = Jwts.builder().signWith(key).content(contentStream).encodePayload(false).compact()

        // But verify with 3 types of sources: byte array, and two different kinds of InputStreams:
        InputStream asByteInputStream =Streams.of(content)
        InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(content))

        for (def payload : [content, asByteInputStream, asBufferedInputStream]) {
            def parser = Jwts.parser().verifyWith(key).build()
            def jws
            if (payload instanceof byte[]) {
                jws = parser.parseSignedContent(s, (byte[]) payload)
            } else {
                jws = parser.parseSignedContent(s, (InputStream) payload)
            }
            // When the supplied unencodedPayload is not a byte array or a ByteArrayInputStream, we can't know how
            // big the payload stream might be, and we don't want to pull it all into memory, so the JWS payload
            // body will be empty.  So we only assert the payload contents when we can get the bytes:
            if (payload instanceof byte[] || payload instanceof ByteArrayInputStream) {
                assertArrayEquals content, jws.getPayload()
            } else {
                assertArrayEquals Bytes.EMPTY, jws.getPayload()
            }
        }
    }

    @Test
    void payloadStreamThatDoesNotSupportMark() {
        def key = TestKeys.HS256
        String s = 'Hello JJWT'
        byte[] data = Strings.utf8(s)
        InputStream stream = new ByteArrayInputStream(data) {
            @Override
            boolean markSupported() {
                return false
            }

            @Override
            void mark(int readAheadLimit) {
                throw new UnsupportedOperationException("Not supported.")
            }
        }

        // compact/sign shouldn't fail, should still compute signature:
        String compact = Jwts.builder().content(stream).signWith(key).encodePayload(false).compact()

        // signature still verified:
        def jwt = Jwts.parser().verifyWith(key).build().parseSignedContent(compact, data)
        assertEquals 'HS256', jwt.header.getAlgorithm()
        assertEquals s, Strings.utf8(jwt.getPayload())
    }

    @Test
    void testClaimsPayload() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('{"sub":"me"}')

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).build().parseSignedClaims(s, payload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    /**
     * Asserts that, even if the parser builder is not explicitly called with .critical("b64") to indicate B64 payloads
     * are supported, that a call to .parse*Jws(String, unencodedPayload) still works.  Just the fact that the
     * overloaded method is called explicitly means they want B64 payload support, so it should still 'just work'
     * even if .critical isn't configured.
     */
    @Test
    void critUnspecifiedOnParserBuilder() {

        def key = TestKeys.HS256

        byte[] payload = Strings.utf8('{"sub":"me"}')

        String s = Jwts.builder().signWith(key).content(payload).encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key) // .critical("b64") is not called, should still work:
                .build().parseSignedClaims(s, payload)

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
            Jwts.parser().verifyWith(TestKeys.HS256).build().parseSignedContent('whatever', Bytes.EMPTY) // <-- empty
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = 'unencodedPayload argument cannot be null or empty.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseClaimsWithEmptyBytesPayload() {
        try {
            Jwts.parser().verifyWith(TestKeys.HS256).build().parseSignedClaims('whatever', Bytes.EMPTY) // <-- empty
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
            Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                    .parseSignedContent(s) // <-- no payload supplied
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
            Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                    .parseSignedClaims(s) // <-- no payload supplied
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

        def jws = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedContent(s) // <--- parse normally, without calling parseSignedContent(s, unencodedPayload)

        assertArrayEquals Strings.utf8(payload), jws.getPayload()
    }

    @Test
    void testNonDetachedClaims() {

        def key = TestKeys.HS256

        // create a non-detached unencoded JWS:
        String s = Jwts.builder().signWith(key).subject('me').encodePayload(false).compact()

        def jws = Jwts.parser().verifyWith(key).critical().add(DefaultJwsHeader.B64.id).and().build()
                .parseSignedClaims(s) // <--- parse normally, without calling parseSignedClaims(s, unencodedPayload)

        assertEquals 'me', jws.getPayload().getSubject()
    }

    @Test
    void testDecompression() {

        def key = TestKeys.HS256

        byte[] content = Strings.utf8('hello world')

        for (def zip : Jwts.ZIP.get().values()) {

            ByteArrayOutputStream out = new ByteArrayOutputStream()
            OutputStream cos = zip.compress(out); cos.write(content); cos.close()
            def compressed = out.toByteArray()

            // create a detached unencoded JWS that is compressed:
            String s = Jwts.builder().signWith(key).content(content).encodePayload(false)
                    .compressWith(zip)
                    .compact()

            // But verify with 3 types of sources: byte array, and two different kinds of InputStreams:
            InputStream asByteInputStream = Streams.of(compressed)
            InputStream asBufferedInputStream = new BufferedInputStream(Streams.of(compressed))

            for (def payload : [compressed, asByteInputStream, asBufferedInputStream]) {
                def parser = Jwts.parser().verifyWith(key).build()
                def jws
                if (payload instanceof byte[]) {
                    jws = parser.parseSignedContent(s, (byte[]) payload)
                } else {
                    jws = parser.parseSignedContent(s, (InputStream) payload)
                }
                // When the supplied unencodedPayload is not a byte array or a ByteArrayInputStream, we can't know how
                // big the payload stream might be, and we don't want to pull it all into memory, so the JWS payload
                // body will be empty.  So we only assert the payload contents when we can get the bytes:
                if (payload instanceof byte[] || payload instanceof ByteArrayInputStream) {
                    assertArrayEquals content, jws.getPayload()
                } else {
                    assertArrayEquals Bytes.EMPTY, jws.getPayload()
                }
            }
        }
    }

    /**
     * Safe decompression of an unencoded payload using a SigningKeyResolver (SKR) is not possible because the SKR
     * only verifies signatures after payloads are enabled, and signatures need to be verified before the payload
     * is trusted.  And decompressing an unsecured payload is a security risk.
     */
    @SuppressWarnings('GrDeprecatedAPIUsage')
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
            Jwts.parser()
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        Key resolveSigningKey(JwsHeader header, byte[] content) {
                            return key
                        }
                    })
                    .build()
                    .parseSignedContent(s, payload)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.B64_DECOMPRESSION_MSG, zip.id)
            assertEquals msg, expected.message
        }
    }
}

/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.*
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Keys
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParser
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.

class DefaultJwtParserTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test(expected = IllegalArgumentException)
    void testBase64UrlDecodeWithNullArgument() {
        new DefaultJwtParser().base64UrlDecodeWith(null)
    }

    @Test
    void testBase64UrlDecodeWithCustomDecoder() {
        def decoder = new Decoder() {
            @Override
            Object decode(Object o) throws DecodingException {
                return null
            }
        }
        def b = new DefaultJwtParser().base64UrlDecodeWith(decoder)
        assertSame decoder, b.base64UrlDecoder
    }

    @Test(expected = MalformedJwtException)
    void testBase64UrlDecodeWithInvalidInput() {
        new DefaultJwtParser().base64UrlDecode('20:SLDKJF;3993;----', 'test')
    }

    @Test(expected = IllegalArgumentException)
    void testDeserializeJsonWithNullArgument() {
        new DefaultJwtParser().deserializeJsonWith(null)
    }

    @Test
    void testDesrializeJsonWithCustomSerializer() {
        def deserializer = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                return OBJECT_MAPPER.readValue(bytes, Map.class)
            }
        }
        def p = new DefaultJwtParser().deserializeJsonWith(deserializer)
        assertSame deserializer, p.deserializer

        def key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String jws = Jwts.builder().claim('foo', 'bar').signWith(key, SignatureAlgorithm.HS256).compact()

        assertEquals 'bar', p.setSigningKey(key).parseClaimsJws(jws).getBody().get('foo')
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithMissingAlg() {

        String header = Encoders.BASE64URL.encode('{"foo":"bar"}'.getBytes(Strings.UTF_8))
        String body = Encoders.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithNullAlg() {

        String header = Encoders.BASE64URL.encode('{"alg":null}'.getBytes(Strings.UTF_8))
        String body = Encoders.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithEmptyAlg() {

        String header = Encoders.BASE64URL.encode('{"alg":"  "}'.getBytes(Strings.UTF_8))
        String body = Encoders.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }

    @Test
    void testMaxAllowedClockSkewSeconds() {
        long max = Long.MAX_VALUE / 1000 as long
        new DefaultJwtParser().setAllowedClockSkewSeconds(max) // no exception should be thrown
    }

    @Test
    void testExceededAllowedClockSkewSeconds() {
        long value = Long.MAX_VALUE / 1000 as long
        value = value + 1L
        try {
            new DefaultJwtParser().setAllowedClockSkewSeconds(value)
        } catch (IllegalArgumentException expected) {
            assertEquals DefaultJwtParserBuilder.MAX_CLOCK_SKEW_ILLEGAL_MSG, expected.message
        }
    }
}

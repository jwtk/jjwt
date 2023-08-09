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
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Keys
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParser
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.

class DefaultJwtParserTest {

    // all whitespace chars as defined by Character.isWhitespace:
    static final String WHITESPACE_STR = ' \u0020 \u2028 \u2029 \t \n \u000B \f \r \u001C \u001D \u001E \u001F '

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private DefaultJwtParser newParser() {
        return Jwts.parser().build() as DefaultJwtParser
    }

    @Test(expected = MalformedJwtException)
    void testBase64UrlDecodeWithInvalidInput() {
        newParser().decode('20:SLDKJF;3993;----', 'test')
    }

    @Test
    void testDesrializeJsonWithCustomSerializer() {
        def deserializer = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                return OBJECT_MAPPER.readValue(bytes, Map.class)
            }
        }
        def pb = Jwts.parser().deserializeJsonWith(deserializer)
        def p = pb.build() as DefaultJwtParser
        assertTrue("Expected wrapping deserializer to be instance of JwtDeserializer", p.deserializer instanceof JwtDeserializer )
        assertSame deserializer, p.deserializer.deserializer

        def key = Jwts.SIG.HS256.key().build()

        String jws = Jwts.builder().claim('foo', 'bar').signWith(key, Jwts.SIG.HS256).compact()

        assertEquals 'bar', pb.verifyWith(key).build().parseClaimsJws(jws).getPayload().get('foo')
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

        Jwts.parser().verifyWith(key).build().parseClaimsJws(invalidJws)
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

        Jwts.parser().verifyWith(key).build().parseClaimsJwe(invalidJws)
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

        Jwts.parser().verifyWith(key).build().parseClaimsJws(invalidJws)
    }

    @Test
    void testIsLikelyJsonWithEmptyString() {
        assertFalse DefaultJwtParser.isLikelyJson(''.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithEmptyBytes() {
        assertFalse DefaultJwtParser.isLikelyJson(Bytes.EMPTY)
    }

    @Test
    void testIsLikelyJsonWithWhitespaceString() {
        assertFalse DefaultJwtParser.isLikelyJson(WHITESPACE_STR.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithOnlyOpeningBracket() {
        assertFalse DefaultJwtParser.isLikelyJson(' {... '.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithOnlyClosingBracket() {
        assertFalse DefaultJwtParser.isLikelyJson(' } '.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonMinimalJsonObject() {
        assertTrue DefaultJwtParser.isLikelyJson("{}".getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithLeadingAndTrailingWhitespace() {
        // all whitespace chars as defined by Character.isWhitespace:
        String claimsJson = WHITESPACE_STR + '{"sub":"joe"}' + WHITESPACE_STR
        assertTrue DefaultJwtParser.isLikelyJson(claimsJson.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithLeadingTextBeforeJsonObject() {
        // all whitespace chars as defined by Character.isWhitespace:
        String claimsJson = ' x {"sub":"joe"}'
        assertFalse DefaultJwtParser.isLikelyJson(claimsJson.getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testIsLikelyJsonWithTrailingTextAfterJsonObject() {
        // all whitespace chars as defined by Character.isWhitespace:
        String claimsJson = '{"sub":"joe"} x'
        assertFalse DefaultJwtParser.isLikelyJson(claimsJson.getBytes(StandardCharsets.UTF_8))
    }
}

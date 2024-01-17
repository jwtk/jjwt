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
import io.jsonwebtoken.*
import io.jsonwebtoken.impl.lang.JwtDateConverter
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.AbstractDeserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.lang.DateFormats
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Keys
import org.junit.Before
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey

import static org.junit.Assert.*

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParser
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.

class DefaultJwtParserTest {

    // all whitespace chars as defined by Character.isWhitespace:
    static final String WHITESPACE_STR = ' \u0020 \u2028 \u2029 \t \n \u000B \f \r \u001C \u001D \u001E \u001F '

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private DefaultJwtParser parser

    private static String b64Url(def val) {
        if (val instanceof String) val = Strings.utf8(val)
        return Encoders.BASE64URL.encode(val)
    }

    private static byte[] serialize(Map<String, ?> map) {
        def serializer = Services.get(Serializer)
        ByteArrayOutputStream out = new ByteArrayOutputStream(512)
        serializer.serialize(map, out)
        return out.toByteArray()
    }

    @Before
    void setUp() {
        parser = Jwts.parser().build() as DefaultJwtParser
    }

    @Test(expected = MalformedJwtException)
    void testBase64UrlDecodeWithInvalidInput() {
        parser.decode('20:SLDKJF;3993;----', 'test')
    }

    @Test
    void testDesrializeJsonWithCustomSerializer() {
        boolean invoked = false
        def deserializer = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                invoked = true
                return OBJECT_MAPPER.readValue(reader, Map.class)
            }
        }
        def pb = Jwts.parser().deserializeJsonWith(deserializer)
        assertFalse invoked

        def key = Jwts.SIG.HS256.key().build()
        String jws = Jwts.builder().claim('foo', 'bar').signWith(key, Jwts.SIG.HS256).compact()
        assertFalse invoked

        assertEquals 'bar', pb.verifyWith(key).build().parseSignedClaims(jws).getPayload().get('foo')
        assertTrue invoked
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

        Jwts.parser().verifyWith(key).build().parseSignedClaims(invalidJws)
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

        Jwts.parser().verifyWith(key).build().parseEncryptedClaims(invalidJws)
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

        Jwts.parser().verifyWith(key).build().parseSignedClaims(invalidJws)
    }

    /*
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
     */

    @Test
    void testUnprotectedCritRejected() {
        def map = [alg: "none", crit: ["whatever"]]
        def header = b64Url(serialize(map))
        String compact = header + '.doesntMatter.'
        try {
            Jwts.parser().unsecured().build().parse(compact)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_UNSECURED_MSG, map)
            assertEquals msg, expected.message
        }
    }

    @Test
    void testProtectedCritWithoutAssociatedHeader() {
        def map = [alg: "HS256", crit: ["whatever"]]
        def header = b64Url(serialize(map))
        String compact = header + '.a.b'
        try {
            Jwts.parser().unsecured().build().parse(compact)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_MISSING_MSG, 'whatever', 'whatever', map)
            assertEquals msg, expected.message
        }
    }

    @Test
    void testProtectedCritWithUnsupportedHeader() {
        def map = [alg: "HS256", crit: ["whatever"], whatever: 42]
        def header = b64Url(serialize(map))
        String compact = header + '.a.b'
        try {
            Jwts.parser().unsecured().build().parse(compact)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = String.format(DefaultJwtParser.CRIT_UNSUPPORTED_MSG, 'whatever', 'whatever', map)
            assertEquals msg, expected.message
        }
    }

    @Test
    void testProtectedCritWithSupportedHeader() {
        def key = TestKeys.HS256
        def crit = Collections.setOf('whatever')
        String jws = Jwts.builder()
                .header().critical().add(crit).and().add('whatever', 42).and()
                .subject('me')
                .signWith(key).compact()

        def jwt = Jwts.parser().critical().add(crit).and().verifyWith(key).build().parseSignedClaims(jws)

        // no exception thrown, as expected, check the header values:
        def parsedCrit = jwt.getHeader().getCritical()
        assertEquals 1, parsedCrit.size()
        assertEquals 'whatever', parsedCrit.iterator().next()
        assertEquals 42, jwt.getHeader().get('whatever')
    }

    @Test
    void testExpiredExceptionMessage() {

        long differenceMillis = 843 // arbitrary, anything > 0 is fine
        def exp = JwtDateConverter.INSTANCE.applyFrom(System.currentTimeMillis() / 1000L)
        def later = new Date(exp.getTime() + differenceMillis)
        def s = Jwts.builder().expiration(exp).compact()

        try {
            Jwts.parser().unsecured().clock(new FixedClock(later)).build().parse(s)
        } catch (ExpiredJwtException expected) {
            def exp8601 = DateFormats.formatIso8601(exp, true)
            def later8601 = DateFormats.formatIso8601(later, true)
            String msg = "JWT expired ${differenceMillis} milliseconds ago at ${exp8601}. " +
                    "Current time: ${later8601}. Allowed clock skew: 0 milliseconds.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testNotBeforeExceptionMessage() {

        long differenceMillis = 3842 // arbitrary, anything > 0 is fine
        def nbf = JwtDateConverter.INSTANCE.applyFrom(System.currentTimeMillis() / 1000L)
        def earlier = new Date(nbf.getTime() - differenceMillis)
        def s = Jwts.builder().notBefore(nbf).compact()

        try {
            Jwts.parser().unsecured().clock(new FixedClock(earlier)).build().parseUnsecuredClaims(s)
        } catch (PrematureJwtException expected) {
            def nbf8601 = DateFormats.formatIso8601(nbf, true)
            def earlier8601 = DateFormats.formatIso8601(earlier, true)
            String msg = "JWT early by ${differenceMillis} milliseconds before ${nbf8601}. " +
                    "Current time: ${earlier8601}. Allowed clock skew: 0 milliseconds.";
            assertEquals msg, expected.message
        }
    }

    @Test
    void testInvalidB64UrlPayload() {
        def jwt = Encoders.BASE64URL.encode(Strings.utf8('{"alg":"none"}'))
        jwt += ".F!3!#." // <-- invalid Base64URL payload
        try {
            Jwts.parser().unsecured().build().parse(jwt)
            fail()
        } catch (MalformedJwtException expected) {
            String msg = 'Invalid Base64Url payload: <redacted>'
            assertEquals msg, expected.message
        }
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void deprecatedAliases() { // TODO: delete this test when deleting these deprecated methods:

        // parseContentJwt
        byte[] data = Strings.utf8('hello')
        def jwt = Jwts.builder().content(data).compact()
        assertArrayEquals data, Jwts.parser().unsecured().build().parseContentJwt(jwt).getPayload()

        // parseClaimsJwt
        jwt = Jwts.builder().subject('me').compact()
        assertEquals 'me', Jwts.parser().unsecured().build().parseClaimsJwt(jwt).getPayload().getSubject()

        // parseContentJws
        def key = TestKeys.HS256
        jwt = Jwts.builder().content(data).signWith(key).compact()
        assertArrayEquals data, Jwts.parser().verifyWith(key).build().parseContentJws(jwt).getPayload()

        // parseClaimsJws
        jwt = Jwts.builder().subject('me').signWith(key).compact()
        assertEquals 'me', Jwts.parser().verifyWith(key).build().parseClaimsJws(jwt).getPayload().getSubject()

        //parse(jwt, handler)
        def value = 'foo'
        def handler = new JwtHandlerAdapter() {
            @Override
            Object onClaimsJws(Jws jws) {
                return value
            }
        }
        assertEquals value, Jwts.parser().verifyWith(key).build().parse(jwt, handler)
    }
}

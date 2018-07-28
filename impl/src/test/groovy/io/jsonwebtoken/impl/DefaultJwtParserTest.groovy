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
    void testBase64UrlEncodeWithCustomDecoder() {
        def decoder = new Decoder() {
            @Override
            Object decode(Object o) throws DecodingException {
                return null
            }
        }
        def b = new DefaultJwtParser().base64UrlDecodeWith(decoder)
        assertSame decoder, b.base64UrlDecoder
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
}

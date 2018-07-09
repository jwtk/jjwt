package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.codec.Decoder
import io.jsonwebtoken.codec.DecodingException
import io.jsonwebtoken.codec.Encoder
import io.jsonwebtoken.impl.crypto.MacProvider
import io.jsonwebtoken.io.impl.orgjson.OrgJsonDeserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParser
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.

class DefaultJwtParserTest {

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
        def deserializer = new OrgJsonDeserializer()
        def p = new DefaultJwtParser().deserializeJsonWith(deserializer)
        assertSame deserializer, p.deserializer

        def key = MacProvider.generateKey(SignatureAlgorithm.HS256)

        String jws = Jwts.builder().claim('foo', 'bar').signWith(SignatureAlgorithm.HS256, key).compact()

        assertEquals 'bar', p.setSigningKey(key).parseClaimsJws(jws).getBody().get('foo')
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithMissingAlg() {

        String header = Encoder.BASE64URL.encode('{"foo":"bar"}'.getBytes(Strings.UTF_8))
        String body = Encoder.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoder.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithNullAlg() {

        String header = Encoder.BASE64URL.encode('{"alg":null}'.getBytes(Strings.UTF_8))
        String body = Encoder.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoder.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }

    @Test(expected = MalformedJwtException)
    void testParseJwsWithEmptyAlg() {

        String header = Encoder.BASE64URL.encode('{"alg":"  "}'.getBytes(Strings.UTF_8))
        String body = Encoder.BASE64URL.encode('{"hello":"world"}'.getBytes(Strings.UTF_8))
        String compact = header + '.' + body + '.'

        SecretKey key = MacProvider.generateKey(SignatureAlgorithm.HS256)
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Strings.UTF_8))
        String encodedSignature = Encoder.BASE64URL.encode(signatureBytes)

        String invalidJws = compact + encodedSignature

        new DefaultJwtParser().setSigningKey(key).parseClaimsJws(invalidJws)
    }
}

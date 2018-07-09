package io.jsonwebtoken.impl

import io.jsonwebtoken.codec.Decoder
import io.jsonwebtoken.codec.DecodingException
import org.junit.Test
import static org.junit.Assert.*

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParser
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.

class DefaultJwtParserTest {

    @Test(expected = IllegalArgumentException)
    void testBase64UrlDecodeWithNullArgument() {
        new DefaultJwtBuilder().base64UrlEncodeWith(null)
    }

    @Test
    void testBase64UrlEncodeWithCustomEncoder() {
        def decoder = new Decoder() {
            @Override
            Object decode(Object o) throws DecodingException {
                return null
            }
        }
        def b = new DefaultJwtParser().base64UrlDecodeWith(decoder)
        assertSame decoder, b.base64UrlDecoder
    }
}

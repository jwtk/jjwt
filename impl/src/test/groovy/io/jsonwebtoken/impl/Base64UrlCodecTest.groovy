package io.jsonwebtoken.impl

import io.jsonwebtoken.lang.Strings
import org.junit.Test
import static org.junit.Assert.*

@Deprecated //remove just before 1.0.0 release
class Base64UrlCodecTest {

    @Test
    void testEncodeDecode() {

        String s = "Hello 世界"

        def codec = new Base64UrlCodec()

        String base64url = codec.encode(s.getBytes(Strings.UTF_8))

        byte[] decoded = codec.decode(base64url)

        String result = new String(decoded, Strings.UTF_8)

        assertEquals s, result
    }
}

package io.jsonwebtoken.impl

import org.junit.Test

import static org.junit.Assert.assertEquals

@Deprecated //remove just before 1.0.0 release
class Base64CodecTest {

    @Test
    void testEncodeDecode() {

        String s = "Hello 世界"

        def codec = new Base64Codec()

        String encoded = codec.encode(s)

        assertEquals s, codec.decodeToString(encoded)
    }

}

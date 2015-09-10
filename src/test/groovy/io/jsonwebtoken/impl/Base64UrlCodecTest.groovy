package io.jsonwebtoken.impl

import org.junit.Test
import static org.junit.Assert.*

class Base64UrlCodecTest {

    @Test
    void testRemovePaddingWithEmptyByteArray() {

        def codec = new Base64UrlCodec()

        byte[] empty = new byte[0];

        def result = codec.removePadding(empty)

        assertSame empty, result
    }
}

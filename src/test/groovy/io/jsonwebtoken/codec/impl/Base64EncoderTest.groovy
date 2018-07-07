package io.jsonwebtoken.codec.impl

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.assertEquals

class Base64EncoderTest {

    @Test(expected = IllegalArgumentException)
    void testEncodeWithNullArgument() {
        new Base64Encoder().encode(null)
    }

    @Test
    void testDecode() {
        String input = 'Hello 世界'
        byte[] bytes = input.getBytes(Strings.UTF_8)
        String encoded = new Base64Encoder().encode(bytes)
        assertEquals 'SGVsbG8g5LiW55WM', encoded
    }
}

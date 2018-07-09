package io.jsonwebtoken.codec.impl

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.assertEquals

class Base64DecoderTest {

    @Test(expected = IllegalArgumentException)
    void testDecodeWithNullArgument() {
        new Base64Decoder().decode(null)
    }

    @Test
    void testDecode() {
        String encoded = 'SGVsbG8g5LiW55WM' // Hello 世界
        byte[] bytes = new Base64Decoder().decode(encoded)
        String result = new String(bytes, Strings.UTF_8)
        assertEquals 'Hello 世界', result
    }
}

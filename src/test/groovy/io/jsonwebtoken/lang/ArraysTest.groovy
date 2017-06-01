package io.jsonwebtoken.lang

import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class ArraysTest {

    @Test
    void testCleanWithNull() {
        assertNull Arrays.clean(null)
    }

    @Test
    void testCleanWithEmpty() {
        assertNull Arrays.clean(new byte[0])
    }

    @Test
    void testCleanWithElements() {
        byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8)
        assertSame bytes, Arrays.clean(bytes)
    }

    @Test
    void testByteArrayLengthWithNull() {
        assertEquals 0, Arrays.length(null)
    }

    @Test
    void testByteArrayLengthWithEmpty() {
        assertEquals 0, Arrays.length(new byte[0])
    }

    @Test
    void testByteArrayLengthWithElements() {
        byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8)
        assertEquals 5, Arrays.length(bytes)
    }
}

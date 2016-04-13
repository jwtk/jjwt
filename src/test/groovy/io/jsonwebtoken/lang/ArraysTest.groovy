package io.jsonwebtoken.lang

import groovy.json.internal.Charsets
import org.junit.Test
import static org.junit.Assert.*

class ArraysTest {

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
        byte[] bytes = "hello".getBytes(Charsets.UTF_8)
        assertEquals 5, Arrays.length(bytes)
    }
}

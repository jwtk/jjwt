package io.jsonwebtoken

import org.junit.Test

import static org.junit.Assert.assertEquals

class UnsupportedJwtExceptionTest {

    @Test
    void testStringConstructor() {
        def exception = new UnsupportedJwtException("my message")
        assertEquals "my message", exception.getMessage()
    }

    @Test
    void testCauseConstructor() {
        def ioException = new IOException("root error")
        def exception = new UnsupportedJwtException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

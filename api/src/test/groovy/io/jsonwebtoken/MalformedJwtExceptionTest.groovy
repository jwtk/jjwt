package io.jsonwebtoken

import org.junit.Test

import static org.junit.Assert.assertEquals

class MalformedJwtExceptionTest {

    @Test
    void testStringConstructor() {
        def exception = new MalformedJwtException("my message")
        assertEquals "my message", exception.getMessage()
    }

    @Test
    void testCauseConstructor() {
        def ioException = new IOException("root error")
        def exception = new MalformedJwtException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertEquals

class SignatureExceptionTest {

    @Test
    void testStringConstructor() {
        def exception = new SignatureException("my message")
        assertEquals "my message", exception.getMessage()
    }

    @Test
    void testCauseConstructor() {
        def ioException = new IOException("root error")
        def exception = new SignatureException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}
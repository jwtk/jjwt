package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertEquals

class InvalidKeyExceptionTest {

    @Test
    void testDefaultConstructor() {
        def msg = "my message"
        def exception = new InvalidKeyException(msg)
        assertEquals msg, exception.getMessage()
    }

    @Test
    void testConstructorWithCause() {
        def rootMsg = 'root error'
        def msg = 'wrapping'
        def ioException = new IOException(rootMsg)
        def exception = new InvalidKeyException(msg, ioException)
        assertEquals msg, exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

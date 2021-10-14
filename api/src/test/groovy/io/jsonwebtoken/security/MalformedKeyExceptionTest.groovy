package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertEquals

class MalformedKeyExceptionTest {

    @Test
    void testDefaultConstructor() {
        def msg = "my message"
        def exception = new MalformedKeyException(msg)
        assertEquals msg, exception.getMessage()
    }

    @Test
    void testConstructorWithCause() {
        def rootMsg = 'root error'
        def msg = 'wrapping'
        def ioException = new IOException(rootMsg)
        def exception = new MalformedKeyException(msg, ioException)
        assertEquals msg, exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

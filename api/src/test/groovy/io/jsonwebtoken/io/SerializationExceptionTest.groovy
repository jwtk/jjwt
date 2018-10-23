package io.jsonwebtoken.io

import org.junit.Test

import static org.junit.Assert.assertEquals

class SerializationExceptionTest {

    @Test
    void testDefaultConstructor() {
        def exception = new SerializationException("my message")
        assertEquals "my message", exception.getMessage()
    }

    @Test
    void testConstructorWithCause() {
        def ioException = new java.io.IOException("root error")
        def exception = new SerializationException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

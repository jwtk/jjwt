package io.jsonwebtoken.io

import org.junit.Test

import static org.junit.Assert.assertEquals

class EncodingExceptionTest {

    @Test
    void testConstructorWithCause() {
        def ioException = new java.io.IOException("root error")
        def exception = new EncodingException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

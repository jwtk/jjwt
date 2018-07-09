package io.jsonwebtoken.codec

import org.junit.Test

import static org.junit.Assert.assertEquals

class DecodingExceptionTest {

    @Test
    void testConstructorWithCause() {
        def ioException = new IOException("root error")
        def exception = new DecodingException("wrapping", ioException)
        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}

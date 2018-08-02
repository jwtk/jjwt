package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.*

class UnsupportedKeyExceptionTest {

    @Test
    void testCauseWithMessage() {
        def cause = new IllegalStateException()
        def msg = 'foo'
        def ex = new UnsupportedKeyException(msg, cause)
        assertEquals msg, ex.getMessage()
        assertSame cause, ex.getCause()
    }
}

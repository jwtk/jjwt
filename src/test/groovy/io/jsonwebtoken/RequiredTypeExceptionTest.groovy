package io.jsonwebtoken

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class RequiredTypeExceptionTest {
    @Test
    void testOverloadedConstructor() {
        def msg = 'foo'
        def cause = new NullPointerException()

        def ex = new RequiredTypeException(msg, cause)

        assertEquals ex.message, msg
        assertSame ex.cause, cause
    }

}

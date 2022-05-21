package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.security.SecurityException
import org.junit.Test

import static org.junit.Assert.assertSame

class PropagatingExceptionFunctionTest {

    @Test
    void testAssignableException() {

        def ex = new SecurityException("test")

        def fn = new PropagatingExceptionFunction<>(new Function<Object, Object>() {
            @Override
            Object apply(Object t) {
                throw ex
            }
        }, SecurityException.class, "foo")

        try {
            fn.apply("hi")
        } catch (Exception thrown) {
            assertSame ex, thrown //because it was assignable, 'thrown' should not be a wrapper exception
        }
    }
}

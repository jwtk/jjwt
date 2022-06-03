package io.jsonwebtoken.impl.lang


import io.jsonwebtoken.security.SecurityException
import org.junit.Test

import static org.junit.Assert.assertEquals
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

    @Test
    void testExceptionMessageWithTrailingPeriod() {
        String msg = 'foo.'
        def ex = new IllegalArgumentException("test")
        def fn = new PropagatingExceptionFunction<>(new Function<Object, Object>() {
            @Override
            Object apply(Object t) {
                throw ex
            }
        }, SecurityException.class, msg)

        try {
            fn.apply("hi")
        } catch (SecurityException expected) {
            String expectedMsg ="$msg Cause: test" // expect $msg unaltered
            assertEquals expectedMsg, expected.getMessage()
        }
    }

    @Test
    void testExceptionMessageWithoutTrailingPeriod() {
        String msg = 'foo'
        def ex = new IllegalArgumentException("test")
        def fn = new PropagatingExceptionFunction<>(new Function<Object, Object>() {
            @Override
            Object apply(Object t) {
                throw ex
            }
        }, SecurityException.class, msg)

        try {
            fn.apply("hi")
        } catch (SecurityException expected) {
            String expectedMsg ="$msg. Cause: test" // expect $msg to have a trailing period
            assertEquals expectedMsg, expected.getMessage()
        }
    }
}

package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.MalformedJwtException
import org.junit.Test

import static org.junit.Assert.*

class FunctionsTest {

    @Test
    void testWrapFmt() {

        def cause = new IllegalStateException("foo")

        def fn = Functions.wrapFmt(new CheckedFunction<Object, Object>() {
            @Override
            Object apply(Object o) throws Exception {
                throw cause
            }
        }, MalformedJwtException, "format me %s")

        try {
            fn.apply('hi')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "format me hi. Cause: foo"
            assertEquals msg, expected.getMessage()
            assertSame cause, expected.getCause()
        }
    }

    @Test
    void testWrapFmtPropagatesExpectedExceptionTypeWithoutWrapping() {

        def cause = new MalformedJwtException("foo")

        def fn = Functions.wrapFmt(new CheckedFunction<Object, Object>() {
            @Override
            Object apply(Object o) throws Exception {
                throw cause
            }
        }, MalformedJwtException, "format me %s")

        try {
            fn.apply('hi')
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals "foo", expected.getMessage()
            assertSame cause, expected
        }
    }

    @Test
    void testWrap() {

        def cause = new IllegalStateException("foo")

        def fn = Functions.wrap(new Function<Object, Object>() {
            @Override
            Object apply(Object o) {
                throw cause
            }
        }, MalformedJwtException, "format me %s", 'someArg')

        try {
            fn.apply('hi')
            fail()
        } catch (MalformedJwtException expected) {
            String msg = "format me someArg. Cause: foo"
            assertEquals msg, expected.getMessage()
            assertSame cause, expected.getCause()
        }
    }

    @Test
    void testWrapPropagatesExpectedExceptionTypeWithoutWrapping() {

        def cause = new MalformedJwtException("foo")

        def fn = Functions.wrap(new Function<Object, Object>() {
            @Override
            Object apply(Object o) {
                throw cause
            }
        }, MalformedJwtException, "format me %s", 'someArg')

        try {
            fn.apply('hi')
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals "foo", expected.getMessage()
            assertSame cause, expected
        }
    }
}

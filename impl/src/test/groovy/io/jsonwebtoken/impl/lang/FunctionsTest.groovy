/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

    @Test
    void testFirstResultWithNullArgument() {
        try {
            Functions.firstResult(null)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals 'Function list cannot be null or empty.', iae.getMessage()
        }
    }

    @Test
    void testFirstResultWithEmptyArgument() {
        Function<String, String>[] functions = [] as Function<String, String>[]
        try {
            Functions.firstResult(functions)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals 'Function list cannot be null or empty.', iae.getMessage()
        }
    }

    @Test
    void testFirstResultWithSingleNonNullValueFunction() {
        Function<String, String> fn = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s
                return s
            }
        }
        assertEquals 'foo', Functions.firstResult(fn).apply('foo')
    }

    @Test
    void testFirstResultWithSingleNullValueFunction() {
        Function<String, String> fn = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s
                return null
            }
        }
        assertNull Functions.firstResult(fn).apply('foo')
    }

    @Test
    void testFirstResultFallback() {
        def fn1 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s
                return null
            }
        }
        def fn2 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s // ensure original input is retained, not output from fn1
                return 'fn2'
            }
        }
        assertEquals 'fn2', Functions.firstResult(fn1, fn2).apply('foo')
    }

    @Test
    void testFirstResultAllNull() {
        def fn1 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s
                return null
            }
        }
        def fn2 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s // ensure original input is retained, not output from fn1
                return null
            }
        }
        // everything returned null, so null should be returned:
        assertNull Functions.firstResult(fn1, fn2).apply('foo')
    }

    @Test
    void testFirstResultShortCircuit() {
        def fn1 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s
                return null
            }
        }
        def fn2 = new Function<String, String>() {
            @Override
            String apply(String s) {
                assertEquals 'foo', s // ensure original argument is retained, not output from fn1
                return 'fn2'
            }
        }
        boolean invoked = false
        def fn3 = new Function<String, String>() {
            @Override
            String apply(String s) {
                invoked = true // should not be invoked
                return 'fn3'
            }
        }
        assertEquals 'fn2', Functions.firstResult(fn1, fn2, fn3).apply('foo')
        assertFalse invoked
    }
}

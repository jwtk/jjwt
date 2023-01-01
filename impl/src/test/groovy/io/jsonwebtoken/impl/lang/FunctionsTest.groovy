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
}

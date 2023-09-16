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

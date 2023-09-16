/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.lang

import org.junit.Test

import static org.junit.Assert.*

class StringsTest {

    @Test
    void testHasText() {
        assertFalse Strings.hasText(null)
        assertFalse Strings.hasText("")
        assertFalse Strings.hasText("   ")
        assertTrue Strings.hasText("  foo   ")
        assertTrue Strings.hasText("foo")
    }

    @Test
    void testClean() {
        assertEquals "this is a test", Strings.clean("this is a test")
        assertEquals "this is a test", Strings.clean("   this is a test")
        assertEquals "this is a test", Strings.clean("   this is a test   ")
        assertEquals "this is a test", Strings.clean("\nthis is a test \t  ")
        assertNull Strings.clean(null)
        assertNull Strings.clean("")
        assertNull Strings.clean("\t")
        assertNull Strings.clean("      ")
    }

    @Test
    void testCleanCharSequence() {
        def result = Strings.clean(new StringBuilder("this is a test"))
        assertNotNull result
        assertEquals "this is a test", result.toString()

        result = Strings.clean(new StringBuilder("   this is a test"))
        assertNotNull result
        assertEquals "this is a test", result.toString()

        result = Strings.clean(new StringBuilder("   this is a test   "))
        assertNotNull result
        assertEquals "this is a test", result.toString()

        result = Strings.clean(new StringBuilder("\nthis is a test \t  "))
        assertNotNull result
        assertEquals "this is a test", result.toString()

        assertNull Strings.clean((StringBuilder) null)
        assertNull Strings.clean(new StringBuilder(""))
        assertNull Strings.clean(new StringBuilder("\t"))
        assertNull Strings.clean(new StringBuilder("      "))
    }


    @Test
    void testTrimWhitespace() {
        assertEquals "", Strings.trimWhitespace("      ")
    }

    @Test
    void testNespaceNull() {
        assertNull Strings.nespace(null)
    }

    @Test
    void testNespaceEmpty() {
        StringBuilder sb = new StringBuilder()
        Strings.nespace(sb)
        assertEquals 0, sb.length() // didn't add space because it's already empty
        assertEquals '', sb.toString()
    }

    @Test
    void testNespaceNonEmpty() {
        StringBuilder sb = new StringBuilder()
        sb.append("Hello")
        Strings.nespace(sb).append("World")
        assertEquals 'Hello World', sb.toString()
    }
}

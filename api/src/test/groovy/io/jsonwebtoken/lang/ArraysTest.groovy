/*
 * Copyright © 2018 jsonwebtoken.io
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

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class ArraysTest {

    @Test
    void testPrivateCtor() {
        new Arrays() //not allowed in java, including here only to pass test coverage assertions
    }

    @Test
    void testCleanWithNull() {
        assertNull Arrays.clean(null)
    }

    @Test
    void testCleanWithEmpty() {
        assertNull Arrays.clean(new byte[0])
    }

    @Test
    void testCleanWithElements() {
        byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8)
        assertSame bytes, Arrays.clean(bytes)
    }

    @Test
    void testByteArrayLengthWithNull() {
        assertEquals 0, Arrays.length((byte[]) null)
    }

    @Test
    void testByteArrayLengthWithEmpty() {
        assertEquals 0, Arrays.length(new byte[0])
    }

    @Test
    void testByteArrayLengthWithElements() {
        byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8)
        assertEquals 5, Arrays.length(bytes)
    }
}

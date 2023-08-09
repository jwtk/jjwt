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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.Password
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

@SuppressWarnings('GroovyAccessibility')
class PasswordSpecTest {

    private char[] PASSWORD
    private PasswordSpec KEY

    @Before
    void setup() {
        PASSWORD = "whatever".toCharArray()
        KEY = new PasswordSpec(PASSWORD)
    }

    @Test
    void testNewInstance() {
        assertArrayEquals PASSWORD, KEY.toCharArray()
        assertEquals PasswordSpec.NONE_ALGORITHM, KEY.getAlgorithm()
        assertNull KEY.getFormat()
    }

    @Test
    void testGetEncodedUnsupported() {
        try {
            KEY.getEncoded()
            fail()
        } catch (UnsupportedOperationException expected) {
            assertEquals PasswordSpec.ENCODED_DISABLED_MSG, expected.getMessage()
        }
    }

    @Test
    void testSymmetricChange() {
        //assert change in backing array changes key as well:
        PASSWORD[0] = 'b'
        assertArrayEquals PASSWORD, KEY.toCharArray()
    }

    @Test
    void testSymmetricDestroy() {
        KEY.destroy()
        assertTrue KEY.isDestroyed()
        for(char c : PASSWORD) { //assert clearing key clears backing array:
            assertTrue c == (char)'\u0000'
        }
    }

    @Test
    void testDestroyIdempotent() {
        testSymmetricDestroy()
        //now do it again to assert idempotent result:
        KEY.destroy()
        assertTrue KEY.isDestroyed()
        for(char c : PASSWORD) {
            assertTrue c == (char)'\u0000'
        }
    }

    @Test
    void testDestroyPreventsPassword() {
        KEY.destroy()
        try {
            KEY.toCharArray()
            fail()
        } catch (IllegalStateException expected) {
            assertEquals PasswordSpec.DESTROYED_MSG, expected.getMessage()
        }
    }

    @Test
    void testEquals() {
        Password key2 = Keys.password(PASSWORD)
        assertArrayEquals KEY.toCharArray(), key2.toCharArray()
        assertEquals KEY, key2
        assertNotEquals KEY, new Object()
    }

    @Test
    void testIdentityEquals() {
        Password key = Keys.password(PASSWORD)
        assertTrue key.equals(key)
        assertNotEquals KEY, new Object()
    }

    @Test
    void testHashCode() {
        Password key2 = Keys.password(PASSWORD)
        assertArrayEquals KEY.toCharArray(), key2.toCharArray()
        assertEquals KEY.hashCode(), key2.hashCode()
    }

    @Test
    void testToString() {
        assertEquals '<redacted>', KEY.toString()
        Password key2 = Keys.password(PASSWORD)
        assertArrayEquals KEY.toCharArray(), key2.toCharArray()
        assertEquals KEY.toString(), key2.toString()
    }

}

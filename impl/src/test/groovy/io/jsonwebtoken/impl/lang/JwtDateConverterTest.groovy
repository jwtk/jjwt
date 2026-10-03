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

import org.junit.Test

import java.time.Instant

import static org.junit.Assert.*

class JwtDateConverterTest {

    @Test
    void testToDateWithNull() {
        assertNull JwtDateConverter.toDate(null)
    }

    @Test
    void testToDateWithDate() {
        def date = new Date()
        assertSame date, JwtDateConverter.toDate(date)
    }

    @Test
    void testToDateWithCalendar() {
        def cal = Calendar.getInstance()
        assertEquals cal.getTime(), JwtDateConverter.toDate(cal)
    }

    @Test
    void testToDateNumberIsMillis() {
        assertEquals new Date(1700000000123L), JwtDateConverter.toDate(1700000000123L)
    }

    @Test
    void testToDateWithIso8601String() {
        assertEquals Date.from(Instant.parse('2023-11-14T22:13:20.123Z')),
                JwtDateConverter.toDate('2023-11-14T22:13:20.123Z')
    }

    @Test
    void testToDateWithInvalidString() {
        try {
            JwtDateConverter.toDate('not a date')
            fail()
        } catch (IllegalArgumentException expected) {
            assertTrue expected.getMessage().startsWith(
                    'String value is not a JWT NumericDate, nor is it ISO-8601-formatted. All heuristics exhausted.')
        }
    }

    @Test
    void testToDateWithUnsupportedType() {
        try {
            JwtDateConverter.toDate(new Object())
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'Cannot create Date from object of type java.lang.Object.', expected.getMessage()
        }
    }
}

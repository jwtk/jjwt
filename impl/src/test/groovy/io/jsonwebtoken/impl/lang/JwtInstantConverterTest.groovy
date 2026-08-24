/*
 * Copyright © 2026 jsonwebtoken.io
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

import java.time.DateTimeException
import java.time.Instant

import static org.junit.Assert.*

class JwtInstantConverterTest {

    @Test
    void testApplyToNull() {
        assertNull JwtInstantConverter.INSTANCE.applyTo(null)
    }

    @Test
    void testApplyToReturnsSeconds() {
        def instant = Instant.ofEpochSecond(1700000000L, 999_999_999)
        assertEquals 1700000000L, JwtInstantConverter.INSTANCE.applyTo(instant)
    }

    @Test
    void testApplyFromNull() {
        assertNull JwtInstantConverter.INSTANCE.applyFrom(null)
    }

    @Test
    void testApplyFromNumberIsSeconds() {
        assertEquals Instant.ofEpochSecond(1700000000L), JwtInstantConverter.INSTANCE.applyFrom(1700000000L)
        assertEquals Instant.ofEpochSecond(1700000000L), JwtInstantConverter.INSTANCE.applyFrom(1700000000)
    }

    @Test
    void testApplyFromNumericStringIsSeconds() {
        assertEquals Instant.ofEpochSecond(1700000000L), JwtInstantConverter.INSTANCE.applyFrom('1700000000')
    }

    @Test
    void testApplyFromIso8601String() {
        assertEquals Instant.parse('2023-11-14T22:13:20Z'),
                JwtInstantConverter.INSTANCE.applyFrom('2023-11-14T22:13:20Z')
        assertEquals Instant.parse('2023-11-14T22:13:20.123Z'),
                JwtInstantConverter.INSTANCE.applyFrom('2023-11-14T22:13:20.123Z')
    }

    @Test
    void testApplyFromInvalidString() {
        try {
            JwtInstantConverter.INSTANCE.applyFrom('not a date')
            fail()
        } catch (IllegalArgumentException expected) {
            assertTrue expected.getMessage().startsWith(
                    'String value is not a JWT NumericDate, nor is it ISO-8601-formatted. All heuristics exhausted.')
        }
    }

    @Test
    void testApplyFromSecondsOutOfRange() {
        try {
            JwtInstantConverter.INSTANCE.applyFrom(Long.MAX_VALUE)
            fail()
        } catch (IllegalArgumentException expected) {
            assertTrue expected.getMessage().startsWith("Value '${Long.MAX_VALUE}' is outside the supported Instant range.")
            assertTrue expected.getCause() instanceof DateTimeException
        }
    }

    @Test
    void testToInstantWithNull() {
        assertNull JwtInstantConverter.toInstant(null)
    }

    @Test
    void testToInstantWithInstant() {
        def instant = Instant.now()
        assertSame instant, JwtInstantConverter.toInstant(instant)
    }

    @Test
    void testToInstantWithDate() {
        def date = new Date()
        assertEquals date.toInstant(), JwtInstantConverter.toInstant(date)
    }

    @Test
    void testToInstantWithCalendar() {
        def cal = Calendar.getInstance()
        assertEquals cal.toInstant(), JwtInstantConverter.toInstant(cal)
    }

    @Test
    void testToInstantNumberIsMillis() {
        assertEquals Instant.ofEpochMilli(1700000000123L), JwtInstantConverter.toInstant(1700000000123L)
    }

    @Test
    void testToInstantWithUnsupportedType() {
        try {
            JwtInstantConverter.toInstant(new Object())
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'Cannot create Instant from object of type java.lang.Object.', expected.getMessage()
        }
    }

    @Test
    void testToSpecInstantWithInstant() {
        def instant = Instant.now()
        assertSame instant, JwtInstantConverter.toSpecInstant(instant)
    }
}

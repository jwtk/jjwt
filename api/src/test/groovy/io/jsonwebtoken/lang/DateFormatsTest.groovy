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

import java.time.Instant
import java.time.ZoneOffset
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException

import static org.junit.Assert.*

class DateFormatsTest {

    @Test
    void testFormatIso8601WithMillisZuluOffset() {
        final instant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 123000000, ZoneOffset.UTC).toInstant()
        String formattedDate = DateFormats.formatIso8601(instant)
        assertEquals "2023-12-25T15:30:00.123Z", formattedDate
    }

    @Test
    void testFormatIso8601WithMillisNonZuluOffset() {
        final instant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 123000000, ZoneOffset.ofHours(-4)).toInstant()
        String formattedDate = DateFormats.formatIso8601(instant)
        assertEquals "2023-12-25T19:30:00.123Z", formattedDate
    }

    @Test
    void testFormatIso8601WithoutMillisZuluOffset() {
        Instant instant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 0, ZoneOffset.UTC).toInstant()
        String formattedDate = DateFormats.formatIso8601(instant, false)
        assertEquals "2023-12-25T15:30:00Z", formattedDate
    }

    @Test
    void testFormatIso8601WithoutMillisNonZuluOffset() {
        Instant instant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 0, ZoneOffset.ofHours(2)).toInstant()
        String formattedDate = DateFormats.formatIso8601(instant, false)
        assertEquals "2023-12-25T13:30:00Z", formattedDate
    }

    @Test(expected = IllegalArgumentException.class)
    void testFormatIso8601NullInput() {
        DateFormats.formatIso8601(null)
    }

    @Test
    void testParseIso8601DateWithMillisZuluOffset() {
        String dateString = "2023-12-25T15:30:00.123Z"
        Instant parsedDate = DateFormats.parseIso8601Date(dateString)
        assertNotNull(parsedDate)
        final expectedInstant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 123000000, ZoneOffset.UTC).toInstant()
        assertEquals expectedInstant, parsedDate
    }

    @Test
    void testParseIso8601DateWithMillisNonZuluOffset() {
        String dateString = "2023-12-25T15:30:00.123-01:00"
        Instant parsedDate = DateFormats.parseIso8601Date(dateString)
        assertNotNull(parsedDate)
        final expectedInstant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 123000000, ZoneOffset.ofHours(-1)).toInstant()
        assertEquals expectedInstant, parsedDate
    }

    @Test
    void testParseIso8601DateWithoutMillisZuluOffset() {
        String dateString = "2023-12-25T15:30:00Z"
        Instant parsedDate = DateFormats.parseIso8601Date(dateString)
        assertNotNull(parsedDate)
        final expectedInstant = OffsetDateTime.of(2023, 12, 25, 15, 30, 0, 0, ZoneOffset.UTC).toInstant()
        assertEquals expectedInstant, parsedDate
    }

    @Test
    void testParseIso8601DateWithoutMillisNonZuluOffset() {
        String dateString = "2023-12-25T15:30:00+01:00"
        Instant parsedDate = DateFormats.parseIso8601Date(dateString)
        assertNotNull(parsedDate)
        assertEquals OffsetDateTime.of(2023,12,25,15,30,0, 0, ZoneOffset.ofHours(1)).toInstant(), parsedDate
    }

    @Test(expected = DateTimeParseException)
    void testParseIso8601DateInvalidFormat() {
        String invalidDateString = "2023-12-25 15:30"
        DateFormats.parseIso8601Date(invalidDateString)
    }

    @Test(expected = IllegalArgumentException.class)
    void testParseIso8601DateNullInput() {
        DateFormats.parseIso8601Date(null)
    }
}

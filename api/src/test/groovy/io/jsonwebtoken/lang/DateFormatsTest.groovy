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

import java.text.ParseException
import java.text.SimpleDateFormat
import java.time.Instant

import static org.junit.Assert.*

class DateFormatsTest {

    @Test //https://github.com/jwtk/jjwt/issues/291
    void testUtcTimezone() {

        def iso8601 = DateFormats.legacyFormat(DateFormats.ISO_8601_PATTERN)
        def iso8601Millis = DateFormats.legacyFormat(DateFormats.ISO_8601_MILLIS_PATTERN)

        assertTrue iso8601 instanceof SimpleDateFormat
        assertTrue iso8601Millis instanceof SimpleDateFormat

        def utc = TimeZone.getTimeZone("UTC")

        assertEquals utc, iso8601.getTimeZone()
        assertEquals utc, iso8601Millis.getTimeZone()
    }

    @Test //https://github.com/jwtk/jjwt/issues/291
    void testParseIso8601DateUsesUtc() {
        assertEquals Instant.parse('2023-11-14T22:13:20Z'),
                DateFormats.parseIso8601Date('2023-11-14T22:13:20Z').toInstant()
        assertEquals Instant.parse('2023-11-14T22:13:20.123Z'),
                DateFormats.parseIso8601Date('2023-11-14T22:13:20.123Z').toInstant()
    }

    @Test
    void testParseIso8601DateRetainsLenientBehavior() {
        // the deprecated Date variant must keep its pre-0.14.0 lenient SimpleDateFormat behavior:
        assertEquals Instant.parse('2022-01-01T00:00:00Z'),
                DateFormats.parseIso8601Date('2021-13-01T00:00:00Z').toInstant()
    }

    private static final List<Instant> SAMPLES = [
            Instant.EPOCH,
            Instant.ofEpochMilli(1L),
            Instant.ofEpochMilli(-1L),                          // before the epoch
            Instant.ofEpochMilli(1700000000000L),               // no millis
            Instant.ofEpochMilli(1700000000123L),
            Instant.ofEpochMilli(1700000000999L),
            Instant.parse('1999-12-31T23:59:59.999Z'),
            Instant.parse('2024-02-29T12:00:00.050Z'),          // leap day
            Instant.parse('9999-12-31T23:59:59.999Z'),
            Instant.parse('1582-10-15T00:00:00Z')               // first day of the Gregorian calendar
    ]

    private static String legacyFormat(Date date, boolean includeMillis) {
        def pattern = includeMillis ? "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'" : "yyyy-MM-dd'T'HH:mm:ss'Z'"
        def format = new SimpleDateFormat(pattern)
        format.setTimeZone(TimeZone.getTimeZone("UTC"))
        return format.format(date)
    }

    /**
     * Ensures the output is identical to the pre-0.14.0 {@code SimpleDateFormat}-based implementation for all dates
     * between the Gregorian cutover and the year 9999.
     */
    @Test
    void testFormatIso8601MatchesLegacySimpleDateFormat() {
        for (Instant instant : SAMPLES) {
            Date date = Date.from(instant)
            for (boolean millis : [true, false]) {
                String expected = legacyFormat(date, millis)
                assertEquals expected, DateFormats.formatIso8601(date, millis)
                assertEquals expected, DateFormats.formatIso8601(instant, millis)
            }
            assertEquals legacyFormat(date, true), DateFormats.formatIso8601(date)
        }
    }

    @Test(expected = NullPointerException)
    void testFormatIso8601DateNull() {
        DateFormats.formatIso8601((Date) null)
    }

    @Test
    void testFormatIso8601DateAfterYear9999() {
        def date = Date.from(Instant.parse('+10000-01-01T00:00:00Z'))
        assertEquals '+10000-01-01T00:00:00.000Z', DateFormats.formatIso8601(date)
    }

    @Test
    void testFormatIso8601Instant() {
        def instant = Instant.parse('2023-11-14T22:13:20.123Z')
        assertEquals '2023-11-14T22:13:20.123Z', DateFormats.formatIso8601(instant)
        assertEquals '2023-11-14T22:13:20.123Z', DateFormats.formatIso8601(instant, true)
        assertEquals '2023-11-14T22:13:20Z', DateFormats.formatIso8601(instant, false)
    }

    @Test
    void testFormatIso8601InstantTruncatesSubMillis() {
        def instant = Instant.ofEpochSecond(1700000000L, 123999999L)
        assertEquals '2023-11-14T22:13:20.123Z', DateFormats.formatIso8601(instant, true)
        assertEquals '2023-11-14T22:13:20Z', DateFormats.formatIso8601(instant, false)
    }

    @Test(expected = IllegalArgumentException)
    void testFormatIso8601InstantNull() {
        DateFormats.formatIso8601((Instant) null)
    }

    /**
     * Before the Gregorian cutover {@code SimpleDateFormat} used the Julian calendar, while {@code java.time} uses
     * the proleptic Gregorian (ISO-8601) calendar. Both variants now yield the correct ISO-8601 string.
     */
    @Test
    void testFormatIso8601BeforeGregorianCutover() {
        def instant = Instant.parse('0001-01-01T00:00:00Z')
        assertEquals '0001-01-01T00:00:00.000Z', DateFormats.formatIso8601(instant)
        assertEquals '0001-01-01T00:00:00.000Z', DateFormats.formatIso8601(Date.from(instant))
        assertEquals '0001-01-03T00:00:00.000Z', legacyFormat(Date.from(instant), true)
    }

    @Test
    void testParseIso8601Instant() {
        assertEquals Instant.parse('2023-11-14T22:13:20Z'), DateFormats.parseIso8601Instant('2023-11-14T22:13:20Z')
        assertEquals Instant.parse('2023-11-14T22:13:20.123Z'),
                DateFormats.parseIso8601Instant('2023-11-14T22:13:20.123Z')
    }

    @Test
    void testParseIso8601InstantRoundTrip() {
        for (Instant instant : SAMPLES) {
            assertEquals instant, DateFormats.parseIso8601Instant(DateFormats.formatIso8601(instant, true))
            assertEquals instant.getEpochSecond(),
                    DateFormats.parseIso8601Instant(DateFormats.formatIso8601(instant, false)).getEpochSecond()
        }
    }

    @Test
    void testParseIso8601InstantMatchesDate() {
        for (Instant instant : SAMPLES) {
            for (boolean millis : [true, false]) {
                String s = DateFormats.formatIso8601(instant, millis)
                assertEquals DateFormats.parseIso8601Date(s).toInstant(), DateFormats.parseIso8601Instant(s)
            }
        }
    }

    @Test(expected = IllegalArgumentException)
    void testParseIso8601InstantNull() {
        DateFormats.parseIso8601Instant(null)
    }

    @Test
    void testParseIso8601InstantInvalid() {
        def invalid = [
                '',
                'not a date',
                '2023-11-14',                       // no time
                '2023-11-14T22:13:20',              // no 'Z'
                '2023-11-14T22:13:20+01:00',        // offsets are not supported
                '2023-11-14T22:13:20.12Z',          // millis must have 3 digits
                '2023-11-14T22:13:20.1234Z',
                '2023-13-14T22:13:20Z',             // month out of range
                '2023-02-30T22:13:20Z',             // day out of range (lenient parsing would roll over)
                '2023-11-14T24:00:00Z',             // hour out of range
                '2023-11-14T22:13:20Zjunk'          // trailing characters
        ]
        for (String s : invalid) {
            try {
                DateFormats.parseIso8601Instant(s)
                fail("Expected ParseException for '$s'")
            } catch (ParseException expected) {
                assertNotNull expected.getMessage()
                assertNotNull expected.getCause()
            }
        }
    }
}

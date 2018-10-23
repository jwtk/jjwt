package io.jsonwebtoken.lang

import org.junit.Test

import java.text.SimpleDateFormat

import static org.junit.Assert.*

class DateFormatsTest {

    @Test //https://github.com/jwtk/jjwt/issues/291
    void testUtcTimezone() {

        def iso8601 = DateFormats.ISO_8601.get()
        def iso8601Millis = DateFormats.ISO_8601_MILLIS.get()

        assertTrue iso8601 instanceof SimpleDateFormat
        assertTrue iso8601Millis instanceof SimpleDateFormat

        def utc = TimeZone.getTimeZone("UTC")

        assertEquals utc, iso8601.getTimeZone()
        assertEquals utc, iso8601Millis.getTimeZone()
    }
}

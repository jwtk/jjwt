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
package io.jsonwebtoken.lang;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Utility methods to format and parse date strings.
 *
 * @since 0.10.0
 */
public final class DateFormats {

    private DateFormats() {
    } // prevent instantiation

    private static final String ISO_8601_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    private static final String ISO_8601_MILLIS_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    // SimpleDateFormat is only used by the deprecated parseIso8601Date method in order to retain its lenient parsing
    // behavior until it is removed. A new instance is created per call (SimpleDateFormat is not thread-safe) instead
    // of being cached in a ThreadLocal, which would otherwise never be cleaned up in pooled threads. All formatting
    // uses the thread-safe DateTimeFormatter instances below.
    private static DateFormat legacyFormat(String pattern) {
        SimpleDateFormat format = new SimpleDateFormat(pattern);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format;
    }

    // 'uuuu' (proleptic year) instead of 'yyyy' (year-of-era) so that ResolverStyle.STRICT doesn't require an era.
    // DateTimeFormatter instances are immutable and thread-safe, so no ThreadLocal is needed.
    private static final DateTimeFormatter ISO_8601_FORMATTER = isoFormatter("uuuu-MM-dd'T'HH:mm:ss'Z'");

    private static final DateTimeFormatter ISO_8601_MILLIS_FORMATTER = isoFormatter("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'");

    private static final DateTimeFormatter ISO_8601_PARSER = isoFormatter("uuuu-MM-dd'T'HH:mm:ss[.SSS]'Z'");

    private static DateTimeFormatter isoFormatter(String pattern) {
        return DateTimeFormatter.ofPattern(pattern, Locale.ROOT)
                .withZone(ZoneOffset.UTC)
                .withResolverStyle(ResolverStyle.STRICT);
    }

    /**
     * Return an ISO-8601-formatted string with millisecond precision representing the
     * specified {@code date}.
     *
     * @param date the date for which to create an ISO-8601-formatted string
     * @return the date represented as an ISO-8601-formatted string with millisecond precision.
     * @deprecated since 0.14.0 in favor of {@link #formatIso8601(Instant)}. This method will be removed before the
     * JJWT 1.0 release.
     */
    @Deprecated
    public static String formatIso8601(Date date) {
        return formatIso8601(date, true);
    }

    /**
     * Returns an ISO-8601-formatted string with optional millisecond precision for the specified
     * {@code date}.
     *
     * <p>As of 0.14.0, this method delegates to {@link #formatIso8601(Instant, boolean)}. Output is identical to
     * previous versions for any date between the Gregorian calendar cutover (1582-10-15) and the year 9999. Earlier
     * dates are formatted using the proleptic Gregorian calendar instead of the Julian calendar, and years after
     * 9999 are prefixed with a {@code +} sign as required by ISO-8601.</p>
     *
     * @param date          the date for which to create an ISO-8601-formatted string
     * @param includeMillis whether to include millisecond notation within the string.
     * @return the date represented as an ISO-8601-formatted string with optional millisecond precision.
     * @deprecated since 0.14.0 in favor of {@link #formatIso8601(Instant, boolean)}. This method will be removed
     * before the JJWT 1.0 release.
     */
    @Deprecated
    public static String formatIso8601(Date date, boolean includeMillis) {
        return formatIso8601(date.toInstant(), includeMillis);
    }

    /**
     * Parse the specified ISO-8601-formatted date string and return the corresponding {@link Date} instance.  The
     * date string may optionally contain millisecond notation, and those milliseconds will be represented accordingly.
     *
     * @param s the ISO-8601-formatted string to parse
     * @return the string's corresponding {@link Date} instance.
     * @throws ParseException if the specified date string is not a validly-formatted ISO-8601 string.
     * @deprecated since 0.14.0 in favor of {@link #parseIso8601Instant(String)}. This method will be removed before
     * the JJWT 1.0 release.
     */
    @Deprecated
    public static Date parseIso8601Date(String s) throws ParseException {
        Assert.notNull(s, "String argument cannot be null.");
        // assume ISO-8601 with milliseconds if there is a '.', otherwise assume ISO-8601 without millis:
        String pattern = s.lastIndexOf('.') > -1 ? ISO_8601_MILLIS_PATTERN : ISO_8601_PATTERN;
        return legacyFormat(pattern).parse(s);
    }

    /**
     * Return an ISO-8601-formatted string with millisecond precision representing the
     * specified {@code instant}. Any sub-millisecond precision is truncated.
     *
     * @param instant the instant for which to create an ISO-8601-formatted string
     * @return the instant represented as an ISO-8601-formatted string with millisecond precision.
     * @since 0.14.0
     */
    public static String formatIso8601(Instant instant) {
        return formatIso8601(instant, true);
    }

    /**
     * Returns an ISO-8601-formatted string with optional millisecond precision for the specified
     * {@code instant}. Any precision beyond what is included in the string is truncated.
     *
     * <p>For any instant on or after the Gregorian calendar cutover (1582-10-15), the output is identical to that
     * of {@link #formatIso8601(Date, boolean)} for the equivalent {@code Date}. Earlier instants are formatted
     * using the proleptic Gregorian calendar as required by ISO-8601, whereas the {@code Date} variant uses the
     * Julian calendar.</p>
     *
     * @param instant       the instant for which to create an ISO-8601-formatted string
     * @param includeMillis whether to include millisecond notation within the string.
     * @return the instant represented as an ISO-8601-formatted string with optional millisecond precision.
     * @since 0.14.0
     */
    public static String formatIso8601(Instant instant, boolean includeMillis) {
        Assert.notNull(instant, "Instant argument cannot be null.");
        DateTimeFormatter formatter = includeMillis ? ISO_8601_MILLIS_FORMATTER : ISO_8601_FORMATTER;
        return formatter.format(instant);
    }

    /**
     * Parse the specified ISO-8601-formatted date string and return the corresponding {@link Instant}.  The
     * date string may optionally contain millisecond notation, and those milliseconds will be represented accordingly.
     *
     * <p>Unlike {@link #parseIso8601Date(String)}, parsing is strict: out-of-range field values (such as month
     * {@code 13}) and trailing characters are rejected instead of being silently adjusted or ignored, and the
     * millisecond notation, if present, must have exactly three digits. Also, dates before the Gregorian calendar
     * cutover (1582-10-15) are interpreted using the proleptic Gregorian calendar instead of the Julian calendar.</p>
     *
     * @param s the ISO-8601-formatted string to parse
     * @return the string's corresponding {@link Instant}.
     * @throws ParseException if the specified date string is not a validly-formatted ISO-8601 string.
     * @since 0.14.0
     */
    public static Instant parseIso8601Instant(String s) throws ParseException {
        Assert.notNull(s, "String argument cannot be null.");
        try {
            return ISO_8601_PARSER.parse(s, Instant::from);
        } catch (DateTimeParseException e) {
            ParseException pe = new ParseException(e.getMessage(), e.getErrorIndex());
            pe.initCause(e);
            throw pe;
        }
    }
}

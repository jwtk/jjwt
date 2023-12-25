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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Utility methods to format and parse date strings.
 *
 * @since 0.10.0
 */
public final class DateFormats {

    private DateFormats() {
    } // prevent instantiation

    private static final String ISO_8601_PATTERN = "yyyy-MM-dd'T'HH:mm:ssXXX";

    private static final String ISO_8601_MILLIS_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

    private static final ThreadLocal<DateTimeFormatter> ISO_8601 = ThreadLocal.withInitial(() -> DateTimeFormatter.ofPattern(ISO_8601_PATTERN));

    private static final ThreadLocal<DateTimeFormatter> ISO_8601_MILLIS = ThreadLocal.withInitial(() -> DateTimeFormatter.ofPattern(ISO_8601_MILLIS_PATTERN));

    /**
     * Return an ISO-8601-formatted string with millisecond precision representing the
     * specified {@code instant}. Will always convert to UTC timezone.
     *
     * @param instant the date for which to create an ISO-8601-formatted string
     * @return the date represented as an ISO-8601-formatted string in UTC timezone with millisecond precision.
     */
    public static String formatIso8601(Instant instant) {
        return formatIso8601(instant, true);
    }

    /**
     * Returns an ISO-8601-formatted string with optional millisecond precision for the specified
     * {@code instant}. Will always convert to UTC timezone.
     *
     * @param instant           the instant for which to create an ISO-8601-formatted string
     * @param includeMillis     whether to include millisecond notation within the string.
     * @return the date represented as an ISO-8601-formatted string in UTC timezone with optional millisecond precision.
     */
    public static String formatIso8601(Instant instant, boolean includeMillis) {
        Assert.notNull(instant, "Instant argument cannot be null.");
        if (includeMillis) {
            return ISO_8601_MILLIS.get().format(instant.atZone(ZoneOffset.UTC));
        }
        return ISO_8601.get().format(instant.atZone(ZoneOffset.UTC));
    }

    /**
     * Parse the specified ISO-8601-formatted date string and return the corresponding {@link Instant} instance.  The
     * date string may optionally contain millisecond notation, and those milliseconds will be represented accordingly.
     *
     * @param s the ISO-8601-formatted string to parse
     * @return the string's corresponding {@link Instant} instance.
     * @throws DateTimeParseException if the specified date string is not a validly-formatted ISO-8601 string.
     */
    public static Instant parseIso8601Date(String s) throws DateTimeParseException {
        Assert.notNull(s, "String argument cannot be null.");
        if (s.lastIndexOf('.') > -1) { //assume ISO-8601 with milliseconds
            return OffsetDateTime.parse(s, ISO_8601_MILLIS.get()).toInstant();
        } else { //assume ISO-8601 without millis:
            return OffsetDateTime.parse(s, ISO_8601.get()).toInstant();
        }
    }
}

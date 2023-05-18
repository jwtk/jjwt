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
import java.util.Date;
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

    private static final ThreadLocal<DateFormat> ISO_8601 = new ThreadLocal<DateFormat>() {
        @Override
        protected DateFormat initialValue() {
            SimpleDateFormat format = new SimpleDateFormat(ISO_8601_PATTERN);
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format;
        }
    };

    private static final ThreadLocal<DateFormat> ISO_8601_MILLIS = new ThreadLocal<DateFormat>() {
        @Override
        protected DateFormat initialValue() {
            SimpleDateFormat format = new SimpleDateFormat(ISO_8601_MILLIS_PATTERN);
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format;
        }
    };

    /**
     * Return an ISO-8601-formatted string with millisecond precision representing the
     * specified {@code date}.
     *
     * @param date the date for which to create an ISO-8601-formatted string
     * @return the date represented as an ISO-8601-formatted string with millisecond precision.
     */
    public static String formatIso8601(Date date) {
        return formatIso8601(date, true);
    }

    /**
     * Returns an ISO-8601-formatted string with optional millisecond precision for the specified
     * {@code date}.
     *
     * @param date          the date for which to create an ISO-8601-formatted string
     * @param includeMillis whether to include millisecond notation within the string.
     * @return the date represented as an ISO-8601-formatted string with optional millisecond precision.
     */
    public static String formatIso8601(Date date, boolean includeMillis) {
        if (includeMillis) {
            return ISO_8601_MILLIS.get().format(date);
        }
        return ISO_8601.get().format(date);
    }

    /**
     * Parse the specified ISO-8601-formatted date string and return the corresponding {@link Date} instance.  The
     * date string may optionally contain millisecond notation, and those milliseconds will be represented accordingly.
     *
     * @param s the ISO-8601-formatted string to parse
     * @return the string's corresponding {@link Date} instance.
     * @throws ParseException if the specified date string is not a validly-formatted ISO-8601 string.
     */
    public static Date parseIso8601Date(String s) throws ParseException {
        Assert.notNull(s, "String argument cannot be null.");
        if (s.lastIndexOf('.') > -1) { //assume ISO-8601 with milliseconds
            return ISO_8601_MILLIS.get().parse(s);
        } else { //assume ISO-8601 without millis:
            return ISO_8601.get().parse(s);
        }
    }
}

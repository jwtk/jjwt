/*
 * Copyright © 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.DateFormats;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

public class JwtDateConverter implements Converter<Date, Object> {

    public static final JwtDateConverter INSTANCE = new JwtDateConverter();

    @Override
    public Object applyTo(Date date) {
        if (date == null) {
            return null;
        }
        // https://www.rfc-editor.org/rfc/rfc7519.html#section-2, 'Numeric Date' definition:
        return date.getTime() / 1000L;
    }

    @Override
    public Date applyFrom(Object o) {
        return toSpecDate(o);
    }

    /**
     * Returns an RFC-compatible {@link Date} equivalent of the specified object value using heuristics.
     *
     * @param value object to convert to a {@code Date} using heuristics.
     * @return an RFC-compatible {@link Date} equivalent of the specified object value using heuristics.
     * @since 0.10.0
     */
    public static Date toSpecDate(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            try {
                value = Long.parseLong((String) value);
            } catch (NumberFormatException ignored) { // will try in the fallback toDate method call below
            }
        }
        if (value instanceof Number) {
            // https://github.com/jwtk/jjwt/issues/122:
            // The JWT RFC *mandates* NumericDate values are represented as seconds.
            // Because java.util.Date requires milliseconds, we need to multiply by 1000:
            long seconds = ((Number) value).longValue();
            value = seconds * 1000;
        }
        //v would have been normalized to milliseconds if it was a number value, so perform normal date conversion:
        return toDate(value);
    }

    /**
     * Returns a {@link Date} equivalent of the specified object value using heuristics.
     *
     * @param v the object value to represent as a Date.
     * @return a {@link Date} equivalent of the specified object value using heuristics.
     */
    public static Date toDate(Object v) {
        if (v == null) {
            return null;
        } else if (v instanceof Date) {
            return (Date) v;
        } else if (v instanceof Calendar) { //since 0.10.0
            return ((Calendar) v).getTime();
        } else if (v instanceof Number) {
            //assume millis:
            long millis = ((Number) v).longValue();
            return new Date(millis);
        } else if (v instanceof String) {
            return parseIso8601Date((String) v); //ISO-8601 parsing since 0.10.0
        } else {
            String msg = "Cannot create Date from object of type " + v.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Parses the specified ISO-8601-formatted string and returns the corresponding {@link Date} instance.
     *
     * @param value an ISO-8601-formatted string.
     * @return a {@link Date} instance reflecting the specified ISO-8601-formatted string.
     * @since 0.10.0
     */
    private static Date parseIso8601Date(String value) throws IllegalArgumentException {
        try {
            return DateFormats.parseIso8601Date(value);
        } catch (ParseException e) {
            String msg = "String value is not a JWT NumericDate, nor is it ISO-8601-formatted. " +
                    "All heuristics exhausted. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}

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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.DateFormats;

import java.text.ParseException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;

/**
 * Converts between {@link Instant} values and their RFC 7519
 * <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-2">NumericDate</a> representation (seconds since
 * the epoch).
 *
 * @since 0.14.0
 */
public class JwtInstantConverter implements Converter<Instant, Object> {

    public static final JwtInstantConverter INSTANCE = new JwtInstantConverter();

    @Override
    public Object applyTo(Instant instant) {
        if (instant == null) {
            return null;
        }
        // https://www.rfc-editor.org/rfc/rfc7519.html#section-2, 'Numeric Date' definition:
        return instant.getEpochSecond();
    }

    @Override
    public Instant applyFrom(Object o) {
        return toSpecInstant(o);
    }

    /**
     * Returns an RFC-compatible {@link Instant} equivalent of the specified object value using heuristics. Numeric
     * values (and numeric strings) are interpreted as seconds since the epoch, as mandated by the JWT RFC.
     *
     * @param value object to convert to an {@code Instant} using heuristics.
     * @return an RFC-compatible {@link Instant} equivalent of the specified object value using heuristics.
     * @throws IllegalArgumentException if the value cannot be converted or is out of the supported range.
     */
    public static Instant toSpecInstant(Object value) throws IllegalArgumentException {
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            try {
                value = Long.parseLong((String) value);
            } catch (NumberFormatException ignored) { // will try in the fallback toInstant method call below
            }
        }
        if (value instanceof Number) {
            // https://github.com/jwtk/jjwt/issues/122:
            // The JWT RFC *mandates* NumericDate values are represented as seconds:
            long seconds = ((Number) value).longValue();
            try {
                return Instant.ofEpochSecond(seconds);
            } catch (DateTimeException e) {
                throw outOfRange(value, e);
            }
        }
        return toInstant(value);
    }

    /**
     * Returns an {@link Instant} equivalent of the specified object value using heuristics. Unlike
     * {@link #toSpecInstant(Object)}, numeric values are interpreted as milliseconds since the epoch.
     *
     * @param v the object value to represent as an Instant.
     * @return an {@link Instant} equivalent of the specified object value using heuristics.
     * @throws IllegalArgumentException if the value cannot be converted or is out of the supported range.
     */
    public static Instant toInstant(Object v) throws IllegalArgumentException {
        if (v == null) {
            return null;
        } else if (v instanceof Instant) {
            return (Instant) v;
        } else if (v instanceof Date) {
            return ((Date) v).toInstant();
        } else if (v instanceof Calendar) {
            return ((Calendar) v).toInstant();
        } else if (v instanceof Number) {
            //assume millis:
            long millis = ((Number) v).longValue();
            try {
                return Instant.ofEpochMilli(millis);
            } catch (DateTimeException e) {
                throw outOfRange(v, e);
            }
        } else if (v instanceof String) {
            return parseIso8601Instant((String) v);
        } else {
            String msg = "Cannot create Instant from object of type " + v.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
    }

    private static IllegalArgumentException outOfRange(Object value, Exception cause) {
        String msg = "Value '" + value + "' is outside the supported Instant range. Cause: " + cause.getMessage();
        return new IllegalArgumentException(msg, cause);
    }

    /**
     * Parses the specified ISO-8601-formatted string and returns the corresponding {@link Instant} instance.
     *
     * @param value an ISO-8601-formatted string.
     * @return an {@link Instant} instance reflecting the specified ISO-8601-formatted string.
     */
    private static Instant parseIso8601Instant(String value) throws IllegalArgumentException {
        try {
            return DateFormats.parseIso8601Instant(value);
        } catch (ParseException e) {
            String msg = "String value is not a JWT NumericDate, nor is it ISO-8601-formatted. " +
                    "All heuristics exhausted. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}

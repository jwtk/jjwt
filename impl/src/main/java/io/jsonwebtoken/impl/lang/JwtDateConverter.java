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

import java.time.Instant;
import java.time.format.DateTimeParseException;

public class JwtDateConverter implements Converter<Instant, Object> {

    public static final JwtDateConverter INSTANCE = new JwtDateConverter();

    /**
     * Returns an RFC-compatible {@link Instant} equivalent of the specified object value using heuristics.
     *
     * @param value object to convert to a {@code Instant} using heuristics.
     * @return an RFC-compatible {@link Instant} equivalent of the specified object value using heuristics.
     * @since 0.10.0
     */
    public static Instant toSpecInstant(Object value) {
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
            long seconds = ((Number) value).longValue();
            value = Instant.ofEpochSecond(seconds);
        }
        // would have been normalized to Instant if it was a number value, so perform normal instant conversion:
        return toInstant(value);
    }

    /**
     * Returns a {@link Instant} equivalent of the specified object value using heuristics.
     *
     * @param v the object value to represent as a Date.
     * @return a {@link Instant} equivalent of the specified object value using heuristics.
     */
    public static Instant toInstant(Object v) {
        if (v == null) {
            return null;
        } else if (v instanceof Instant) {
            return (Instant) v;
        } else if (v instanceof Number) {
            //assume millis:
            long millis = ((Number) v).longValue();
            return Instant.ofEpochMilli(millis);
        } else if (v instanceof String) {
            return parseIso8601Date((String) v); //ISO-8601 parsing since 0.10.0
        } else {
            String msg = "Cannot create Instant from object of type " + v.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Parses the specified ISO-8601-formatted string and returns the corresponding {@link Instant} instance.
     *
     * @param value an ISO-8601-formatted string.
     * @return a {@link Instant} instance reflecting the specified ISO-8601-formatted string.
     * @since 0.10.0
     */
    private static Instant parseIso8601Date(String value) throws IllegalArgumentException {
        try {
            return DateFormats.parseIso8601Date(value);
        } catch (DateTimeParseException e) {
            String msg = "String value is not a JWT NumericDate, nor is it ISO-8601-formatted. " +
                    "All heuristics exhausted. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }

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
}

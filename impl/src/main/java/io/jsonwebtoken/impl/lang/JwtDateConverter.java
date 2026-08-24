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

/**
 * Converts object values to {@link Date} instances using heuristics. Retained only to support the deprecated
 * {@code Claims.get(claimName, Date.class)} conversion, which (unlike {@link JwtInstantConverter}) parses ISO-8601
 * strings leniently. RFC NumericDate claims ({@code exp}, {@code nbf} and {@code iat}) are converted by
 * {@link JwtInstantConverter}.
 *
 * <p>This class will be removed along with the deprecated {@code Date}-based APIs before the JJWT 1.0 release.</p>
 */
public final class JwtDateConverter {

    private JwtDateConverter() {
    } // prevent instantiation

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

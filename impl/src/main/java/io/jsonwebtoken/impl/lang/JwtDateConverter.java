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
        // https://datatracker.ietf.org/doc/html/rfc7519#section-2, 'Numeric Date' definition:
        return date.getTime() / 1000L;
    }

    @Override
    public Date applyFrom(Object o) {
        return toSpecDate(o);
    }

    /**
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

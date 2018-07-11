package io.jsonwebtoken.lang;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @since 0.10.0
 */
public class DateFormats {

    private static final String ISO_8601_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    private static final String ISO_8601_MILLIS_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    private static final ThreadLocal<DateFormat> ISO_8601 = new ThreadLocal<DateFormat>() {
        @Override
        protected DateFormat initialValue() {
            return new SimpleDateFormat(ISO_8601_PATTERN);
        }
    };

    private static final ThreadLocal<DateFormat> ISO_8601_MILLIS = new ThreadLocal<DateFormat>() {
        @Override
        protected DateFormat initialValue() {
            return new SimpleDateFormat(ISO_8601_MILLIS_PATTERN);
        }
    };

    public static String formatIso8601(Date date) {
        return formatIso8601(date, true);
    }

    public static String formatIso8601(Date date, boolean includeMillis) {
        if (includeMillis) {
            return ISO_8601_MILLIS.get().format(date);
        }
        return ISO_8601.get().format(date);
    }

    public static Date parseIso8601Date(String s) throws ParseException {
        Assert.notNull(s, "String argument cannot be null.");
        if (s.lastIndexOf('.') > -1) { //assume ISO-8601 with milliseconds
            return ISO_8601_MILLIS.get().parse(s);
        } else { //assume ISO-8601 without millis:
            return ISO_8601.get().parse(s);
        }
    }
}

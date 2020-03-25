package io.jsonwebtoken

final class DateTestUtils {

    /**
     * Date util method for lopping truncate the millis from a date.
     * @param date input date
     * @return The date time in millis with the precision of seconds
     */
    static long truncateMillis(Date date) {
        Calendar cal = Calendar.getInstance()
        cal.setTime(date)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.getTimeInMillis()
    }
}

package io.jsonwebtoken.impl.lang;

abstract class ReflectionFunction<T, R> implements Function<T, R> {

    public static final String ERR_MSG = "Reflection operation failed. This is likely due to an internal " +
            "implementation programming error.  Please report this to the JJWT development team.  Cause: ";

    protected abstract boolean supports(T input);

    protected abstract R invoke(T input) throws Throwable;

    @Override
    public final R apply(T input) {
        if (supports(input)) {
            try {
                return invoke(input);
            } catch (Throwable throwable) {
                // should never happen if supportsInput is true since that would mean we're using the API incorrectly
                String msg = ERR_MSG + throwable.getMessage();
                throw new IllegalStateException(msg, throwable);
            }
        }
        return null;
    }
}

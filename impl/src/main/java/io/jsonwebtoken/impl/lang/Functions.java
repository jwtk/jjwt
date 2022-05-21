package io.jsonwebtoken.impl.lang;

public final class Functions {

    private Functions() {
    }

    /**
     * Wraps the specified function to ensure that if any exception occurs, it is of the specified type and/or with
     * the specified message.  If no exception occurs, the function's return value is returned as expected.
     *
     * <p>If {@code fn} throws an exception, its type is checked.  If it is already of type {@code exClass}, that
     * exception is immediately thrown.  If it is not the expected exception type, a message is created with the
     * specified {@code msg} template, and a new exception of the specified type is thrown with the formatted message,
     * using the original exception as its cause.</p>
     *
     * @param fn      the function to execute
     * @param exClass the exception type expected, if any
     * @param msg     the formatted message to use if throwing a new exception, used as the first argument to {@link String#format(String, Object...) String.format}.
     * @param <T>     the function argument type
     * @param <R>     the function's return type
     * @param <E>     type of exception to ensure
     * @return the wrapping function instance.
     */
    public static <T, R, E extends RuntimeException> Function<T, R> wrapFmt(CheckedFunction<T, R> fn, Class<E> exClass, String msg) {
        return new PropagatingExceptionFunction<>(fn, exClass, new FormattedStringFunction<T>(msg));
    }

    public static <T, R, E extends RuntimeException> Function<T, R> wrap(Function<T, R> fn, Class<E> exClass, String fmt, Object... args) {
        return new PropagatingExceptionFunction<>(new DelegatingCheckedFunction<>(fn), exClass, new FormattedStringSupplier(fmt, args));
    }
}

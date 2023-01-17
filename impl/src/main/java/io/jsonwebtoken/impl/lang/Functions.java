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

    /**
     * Returns a composed function that first applies this function to
     * its input, and then applies the {@code after} function to the result.
     * If evaluation of either function throws an exception, it is relayed to
     * the caller of the composed function.
     *
     * @param <V>   the type of output of the {@code after} function, and of the
     *              composed function
     * @param after the function to apply after this function is applied
     * @return a composed function that first applies this function and then
     * applies the {@code after} function
     * @throws NullPointerException if after is null
     */
    public static <T, V, R> Function<T, R> andThen(final Function<T, ? extends V> before, final Function<V, R> after) {
        return new Function<T, R>() {
            @Override
            public R apply(T t) {
                V result = before.apply(t);
                return after.apply(result);
            }
        };
    }
}

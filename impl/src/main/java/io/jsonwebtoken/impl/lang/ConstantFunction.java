package io.jsonwebtoken.impl.lang;


/**
 * Function that always returns the same value
 *
 * @param <T> Input type
 * @param <R> Return value type
 */
public final class ConstantFunction<T, R> implements Function<T, R> {

    private static final Function<?, ?> NULL = new ConstantFunction<>(null);

    private final R value;

    public ConstantFunction(R value) {
        this.value = value;
    }

    @SuppressWarnings("unchecked")
    public static <T, R> Function<T, R> forNull() {
        return (Function<T, R>) NULL;
    }

    @Override
    public R apply(T t) {
        return this.value;
    }
}

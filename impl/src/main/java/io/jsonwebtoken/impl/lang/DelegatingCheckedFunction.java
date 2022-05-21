package io.jsonwebtoken.impl.lang;

public class DelegatingCheckedFunction<T, R> implements CheckedFunction<T, R> {

    final Function<T, R> delegate;

    public DelegatingCheckedFunction(Function<T, R> delegate) {
        this.delegate = delegate;
    }

    @Override
    public R apply(T t) throws Exception {
        return delegate.apply(t);
    }
}

package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class CompoundConverter<A, B, C> implements Converter<A, C> {

    private final Converter<A, B> first;
    private final Converter<B, C> second;

    public CompoundConverter(Converter<A, B> first, Converter<B, C> second) {
        this.first = Assert.notNull(first, "First converter cannot be null.");
        this.second = Assert.notNull(second, "Second converter cannot be null.");
    }

    @Override
    public C applyTo(A a) {
        B b = first.applyTo(a);
        return second.applyTo(b);
    }

    @Override
    public A applyFrom(C c) {
        B b = second.applyFrom(c);
        return first.applyFrom(b);
    }
}

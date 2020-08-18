package io.jsonwebtoken.impl.lang;

public interface Converter<A,B> {

    B applyTo(A a);

    A applyFrom(B b);
}

package io.jsonwebtoken.impl.lang;

public interface BiFunction<T, U, R> {

    R apply(T t, U u);
}

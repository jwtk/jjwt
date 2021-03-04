package io.jsonwebtoken.impl.lang;

public interface Function<T, R> {

    R apply(T t);
}

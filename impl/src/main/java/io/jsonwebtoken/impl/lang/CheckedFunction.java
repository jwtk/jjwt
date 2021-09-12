package io.jsonwebtoken.impl.lang;

public interface CheckedFunction<T, R> {
    R apply(T t) throws Exception;
}

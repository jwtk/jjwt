package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Identifiable;

public interface Field<T> extends Identifiable, Converter<T, Object> {

    String getName();

    boolean supports(Object value);

    T cast(Object value);

    boolean isSecret();
}

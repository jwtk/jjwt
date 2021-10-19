package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Identifiable;

public interface Field<T> extends Identifiable, Converter<T, Object> {

    String getName();

    Class<T> getIdiomaticType();

    boolean isSecret();

    Converter<T, Object> getConverter();

}

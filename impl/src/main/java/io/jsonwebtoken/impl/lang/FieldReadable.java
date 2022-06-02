package io.jsonwebtoken.impl.lang;

public interface FieldReadable {

    <T> T get(Field<T> field);
}

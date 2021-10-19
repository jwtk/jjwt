package io.jsonwebtoken.impl.lang;

import java.util.List;
import java.util.Set;

public interface FieldBuilder<T> {

    FieldBuilder<T> setId(String id);

    FieldBuilder<T> setName(String name);

    FieldBuilder<T> setSecret(boolean secret);

    <C> FieldBuilder<C> setType(Class<C> type);

    FieldBuilder<List<T>> list();

    FieldBuilder<Set<T>> set();

    FieldBuilder<T> setConverter(Converter<T, ?> converter);

    Field<T> build();

}

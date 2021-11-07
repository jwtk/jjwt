package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Builder;

import java.util.List;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface FieldBuilder<T> extends Builder<Field<T>> {

    FieldBuilder<T> setId(String id);

    FieldBuilder<T> setName(String name);

    FieldBuilder<T> setSecret(boolean secret);

    <C> FieldBuilder<C> setType(Class<C> type);

    FieldBuilder<List<T>> list();

    FieldBuilder<Set<T>> set();

    FieldBuilder<T> setConverter(Converter<T, ?> converter);
}

package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

public class DefaultField<T> implements Field<T> {

    private final String ID;
    private final String NAME;
    private final boolean SECRET;
    private final Class<T> IDIOMATIC_TYPE;
    private final Converter<T, Object> CONVERTER;

    public DefaultField(String id, String name, boolean secret,
                        Class<T> idiomaticType,
                        Converter<T, Object> converter) {
        this.ID = Strings.clean(Assert.hasText(id, "ID argument cannot be null or empty."));
        this.NAME = Strings.clean(Assert.hasText(name, "Name argument cannot be null or empty."));
        this.SECRET = secret;
        this.IDIOMATIC_TYPE = Assert.notNull(idiomaticType, "idiomaticType argument cannot be null.");
        this.CONVERTER = Assert.notNull(converter, "Converter argument cannot be null.");
    }

    @Override
    public String getId() {
        return this.ID;
    }

    @Override
    public String getName() {
        return this.NAME;
    }

    @Override
    public Class<T> getIdiomaticType() {
        return this.IDIOMATIC_TYPE;
    }

    @Override
    public boolean isSecret() {
        return SECRET;
    }

    @Override
    public int hashCode() {
        return this.ID.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Field) {
            return this.ID.equals(((Field<?>) obj).getId());
        }
        return false;
    }

    @Override
    public String toString() {
        return "'" + this.ID + "' (" + this.NAME + ")";
    }

    @Override
    public Object applyTo(T t) {
        return CONVERTER.applyTo(t);
    }

    @Override
    public T applyFrom(Object o) {
        return CONVERTER.applyFrom(o);
    }
}

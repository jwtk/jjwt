package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

import java.util.List;
import java.util.Set;

public class DefaultFieldBuilder<T> implements FieldBuilder<T> {

    private String id;
    private String name;
    private boolean secret;
    private Class<T> type;
    private Converter<T, ?> converter;
    private Boolean list = null; // True == List, False == Set, null == not a collection

    @Override
    public FieldBuilder<T> setId(String id) {
        this.id = id;
        return this;
    }

    @Override
    public FieldBuilder<T> setName(String name) {
        this.name = name;
        return this;
    }

    @Override
    public FieldBuilder<T> setSecret(boolean secret) {
        this.secret = secret;
        return this;
    }

    @SuppressWarnings({"unchecked", "rawtypes", "UnnecessaryLocalVariable"})
    @Override
    public <C> FieldBuilder<C> setType(Class<C> type) {
        Class clazz = type;
        this.type = clazz;
        return (FieldBuilder<C>) this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public FieldBuilder<List<T>> list() {
        this.list = true;
        return (FieldBuilder<List<T>>) this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public FieldBuilder<Set<T>> set() {
        this.list = false;
        return (FieldBuilder<Set<T>>) this;
    }

    @Override
    public FieldBuilder<T> setConverter(Converter<T, ?> converter) {
        this.converter = converter;
        return this;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public Field<T> build() {

        Assert.notNull(this.type, "Type must be set.");
        Converter converter = this.converter;
        if (converter == null) {
            converter = Converters.none(this.type);
        }
        if (this.list != null) {
            converter = this.list ? Converters.forList(converter) : Converters.forSet(converter);
        }

        return new DefaultField<>(this.id, this.name, this.secret, this.type, converter);
    }
}

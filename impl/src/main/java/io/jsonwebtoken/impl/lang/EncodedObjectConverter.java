package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class EncodedObjectConverter<T> implements Converter<T, Object> {

    private final Class<T> type;
    private final Converter<T, String> converter;

    public EncodedObjectConverter(Class<T> type, Converter<T, String> converter) {
        this.type = Assert.notNull(type, "Value type cannot be null.");
        this.converter = Assert.notNull(converter, "Value converter cannot be null.");
    }

    @Override
    public Object applyTo(T t) {
        Assert.notNull(t, "Value argument cannot be null.");
        return converter.applyTo(t);
    }

    @Override
    public T applyFrom(Object value) {
        Assert.notNull(value, "Value argument cannot be null.");
        if (type.isInstance(value)) {
            return type.cast(value);
        } else if (value instanceof String) {
            return converter.applyFrom((String) value);
        } else {
            String msg = "Values must be either String or " + type.getName() +
                " instances. Value type found: " + value.getClass().getName() + ". Value: " + value;
            throw new IllegalArgumentException(msg);
        }
    }
}

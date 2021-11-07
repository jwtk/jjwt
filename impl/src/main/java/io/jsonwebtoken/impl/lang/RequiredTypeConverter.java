package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

/**
 * @since JJWT_RELEASE_VERSION
 */
class RequiredTypeConverter<T> implements Converter<T, Object> {

    private final Class<T> type;

    public RequiredTypeConverter(Class<T> type) {
        this.type = Assert.notNull(type, "type argument cannot be null.");
    }

    @Override
    public Object applyTo(T t) {
        return t;
    }

    @Override
    public T applyFrom(Object o) {
        if (o == null) {
            return null;
        }
        Class<?> clazz = o.getClass();
        if (!type.isAssignableFrom(clazz)) {
            String msg = "Unsupported value type. Expected: " + type.getName() + ", found: " + clazz.getName();
            throw new IllegalArgumentException(msg);
        }
        return type.cast(o);
    }
}
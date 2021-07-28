package io.jsonwebtoken.impl.lang;

class NoConverter<T> implements Converter<T, Object> {

    private final Class<T> type;

    public NoConverter(Class<T> type) {
        this.type = type;
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
            String msg = "Unsupported value type: " + clazz.getName();
            throw new IllegalArgumentException(msg);
        }
        return type.cast(o);
    }
}
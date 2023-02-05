package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;

public class DefaultField<T> implements Field<T> {

    private final String ID;
    private final String NAME;
    private final boolean SECRET;
    private final Class<T> IDIOMATIC_TYPE; // data type, or if collection, element type
    private final Class<? extends Collection<T>> COLLECTION_TYPE; // null if field doesn't represent collection
    private final Converter<T, Object> CONVERTER;

    public DefaultField(String id, String name, boolean secret,
                        Class<T> idiomaticType,
                        Class<? extends Collection<T>> collectionType,
                        Converter<T, Object> converter) {
        this.ID = Strings.clean(Assert.hasText(id, "ID argument cannot be null or empty."));
        this.NAME = Strings.clean(Assert.hasText(name, "Name argument cannot be null or empty."));
        this.IDIOMATIC_TYPE = Assert.notNull(idiomaticType, "idiomaticType argument cannot be null.");
        this.CONVERTER = Assert.notNull(converter, "Converter argument cannot be null.");
        this.SECRET = secret;
        this.COLLECTION_TYPE = collectionType; // can be null if field isn't a collection
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
    public boolean supports(Object value) {
        if (value == null) {
            return true;
        }
        if (COLLECTION_TYPE != null && COLLECTION_TYPE.isInstance(value)) {
            Collection<? extends T> c = COLLECTION_TYPE.cast(value);
            return c.isEmpty() || IDIOMATIC_TYPE.isInstance(c.iterator().next());
        }
        return IDIOMATIC_TYPE.isInstance(value);
    }

    @SuppressWarnings("unchecked")
    @Override
    public T cast(Object value) {
        if (value != null) {
            if (COLLECTION_TYPE != null) { // field represents a collection, ensure it and its elements are the expected type:
                if (!COLLECTION_TYPE.isInstance(value)) {
                    String msg = "Cannot cast " + value.getClass().getName() + " to " +
                            COLLECTION_TYPE.getName() + "<" + IDIOMATIC_TYPE.getName() + ">";
                    throw new ClassCastException(msg);
                }
                Collection<?> c = COLLECTION_TYPE.cast(value);
                if (!c.isEmpty()) {
                    Object element = c.iterator().next();
                    if (!IDIOMATIC_TYPE.isInstance(element)) {
                        String msg = "Cannot cast " + value.getClass().getName() + " to " +
                                COLLECTION_TYPE.getName() + "<" + IDIOMATIC_TYPE.getName() + ">: At least one " +
                                "element is not an instance of " + IDIOMATIC_TYPE.getName();
                        throw new ClassCastException(msg);
                    }
                }
            } else if (!IDIOMATIC_TYPE.isInstance(value)) {
                String msg = "Cannot cast " + value.getClass().getName() + " to " + IDIOMATIC_TYPE.getName();
                throw new ClassCastException(msg);
            }
        }
        return (T) value;
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

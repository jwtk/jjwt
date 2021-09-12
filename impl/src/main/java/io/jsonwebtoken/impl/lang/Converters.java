package io.jsonwebtoken.impl.lang;

import java.util.List;
import java.util.Set;

public final class Converters {

    //prevent instantiation
    private Converters() {
    }

    public static <T> Converter<T, Object> none(Class<T> clazz) {
        return new NoConverter<>(clazz);
    }

    public static <T> Converter<Set<T>, Object> forSet(Converter<T, Object> elementConverter) {
        return CollectionConverter.forSet(elementConverter);
    }

    public static <T> Converter<Set<T>, Object> forSetOf(Class<T> clazz) {
        return forSet(none(clazz));
    }

    public static <T> Converter<List<T>, Object> forList(Converter<T, Object> elementConverter) {
        return CollectionConverter.forList(elementConverter);
    }

    public static <T> Converter<T, Object> forEncoded(Class<T> elementType, Converter<T, String> elementConverter) {
        return new EncodedObjectConverter<T>(elementType, elementConverter);
    }
}

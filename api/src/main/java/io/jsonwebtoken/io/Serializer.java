package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public interface Serializer<T> {

    byte[] serialize(T t) throws SerializationException;

}

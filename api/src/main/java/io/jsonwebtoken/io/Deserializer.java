package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public interface Deserializer<T> {

    T deserialize(byte[] bytes) throws DeserializationException;
}

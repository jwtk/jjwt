package io.jsonwebtoken.io;

public interface Deserializer<T> {

    T deserialize(byte[] bytes) throws DeserializationException;
}

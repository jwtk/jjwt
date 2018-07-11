package io.jsonwebtoken.io;

public interface Serializer<T> {

    byte[] serialize(T t) throws SerializationException;

}

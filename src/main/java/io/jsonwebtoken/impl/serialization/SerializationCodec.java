package io.jsonwebtoken.impl.serialization;

/**
 * Serializes an {@code object} to a {@code byte[]} and deserialize a {@code byte[]} to an {@code object}.
 *
 * @since 0.7.0
 */
public interface SerializationCodec {

    /**
     * Serializes an {@code object} to a {@code byte[]}.
     *
     * @param object
     * @param <T>    the type of object to serialize.
     * @return the serialized object as {@code byte[]}.
     */
    <T> byte[] serialize(T object) throws SerializationException;

    /**
     * Deserialize a {@code byte[]} to an {@code object} of an specific {@code type}
     * <pre>
     * bytes[] serialized = ...
     * Map instance = serializationCodec.deserialize(serialized, Map.class);
     * <pre>
     *
     * @param bytes       of the serialized object.
     * @param targetClass of the instance to return.
     * @param <T>         the specific type of object instance to return.
     * @return A deserialized instance of type {@code T}.
     */
    <T> T deserialize(byte[] bytes, Class<T> targetClass) throws SerializationException;

}
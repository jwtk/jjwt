package io.jsonwebtoken.impl.serialization;

import io.jsonwebtoken.lang.Assert;

import java.io.IOException;

public abstract class AbstractSerializationCodec implements SerializationCodec {

    protected static final String SERIALIZING_ERROR = "Exception occurred while serializing %s to byte[].";

    protected static final String DESERIALIZING_ERROR = "Exception occurred when deserializing byte[] to %s.";

    @Override
    public final <T> byte[] serialize(T object) {
        Assert.notNull(object, "object cannot be null.");
        try {
            return doSerialize(object);
        } catch (IOException e) {
            throw new SerializationException(String.format(SERIALIZING_ERROR, object.getClass().getSimpleName()), e);
        }
    }

    protected abstract <T> byte[] doSerialize(T object) throws IOException;

    @Override
    public final <T> T deserialize(byte[] bytes, Class<T> targetClass) {
        Assert.notNull(bytes, "bytes cannot be null.");
        Assert.notNull(targetClass, "targetClass cannot be null.");
        try {
            return doDeserialize(bytes, targetClass);
        } catch (IOException e) {
            throw new SerializationException(String.format(DESERIALIZING_ERROR, targetClass.getSimpleName()), e);
        }
    }

    protected abstract <T> T doDeserialize(byte[] bytes, Class<T> targetClass) throws IOException;
}
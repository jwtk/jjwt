package io.jsonwebtoken.impl.serialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;

/**
 * Implementation of the {@link SerializationCodec} that relies on Jackson's {@link ObjectMapper objectMapper} to
 * serialize/deserialize objects.
 *
 * @since 0.7.0
 */
public class JacksonSerializationCodec extends AbstractSerializationCodec {

    private final ObjectMapper objectMapper;

    public JacksonSerializationCodec() {
        this(new ObjectMapper());
    }

    public JacksonSerializationCodec(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "objectMapper cannot be null");
        this.objectMapper = objectMapper;
    }

    @Override
    protected <T> T doDeserialize(byte[] bytes, Class<T> typeClass) throws IOException {
        return objectMapper.readValue(bytes, typeClass);
    }

    @Override
    protected <T> byte[] doSerialize(T object) throws IOException {
        return objectMapper.writeValueAsBytes(object);
    }
}

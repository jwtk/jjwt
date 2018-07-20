package io.jsonwebtoken.io;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.lang.Assert;

/**
 * @since 0.10.0
 */
public class JacksonSerializer<T> implements Serializer<T> {

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper();

    private final ObjectMapper objectMapper;

    @SuppressWarnings("unused") //used via reflection by RuntimeClasspathDeserializerLocator
    public JacksonSerializer() {
        this(DEFAULT_OBJECT_MAPPER);
    }

    @SuppressWarnings("WeakerAccess") //intended for end-users to use when providing a custom ObjectMapper
    public JacksonSerializer(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper;
    }

    @Override
    public byte[] serialize(T t) throws SerializationException {
        Assert.notNull(t, "Object to serialize cannot be null.");
        try {
            return writeValueAsBytes(t);
        } catch (JsonProcessingException e) {
            String msg = "Unable to serialize object: " + e.getMessage();
            throw new SerializationException(msg, e);
        }
    }

    @SuppressWarnings("WeakerAccess") //for testing
    protected byte[] writeValueAsBytes(T t) throws JsonProcessingException {
        return this.objectMapper.writeValueAsBytes(t);
    }
}

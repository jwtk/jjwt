package io.jsonwebtoken.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;

/**
 * @since 0.10.0
 */
public class JacksonDeserializer<T> implements Deserializer<T> {

    private final Class<T> returnType;
    private final ObjectMapper objectMapper;

    @SuppressWarnings("unused") //used via reflection by RuntimeClasspathDeserializerLocator
    public JacksonDeserializer() {
        this(JacksonSerializer.DEFAULT_OBJECT_MAPPER);
    }

    @SuppressWarnings({"unchecked", "WeakerAccess", "unused"}) // for end-users providing a custom ObjectMapper
    public JacksonDeserializer(ObjectMapper objectMapper) {
        this(objectMapper, (Class<T>) Object.class);
    }

    private JacksonDeserializer(ObjectMapper objectMapper, Class<T> returnType) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.objectMapper = objectMapper;
        this.returnType = returnType;
    }

    @Override
    public T deserialize(byte[] bytes) throws DeserializationException {
        try {
            return readValue(bytes);
        } catch (IOException e) {
            String msg = "Unable to deserialize bytes into a " + returnType.getName() + " instance: " + e.getMessage();
            throw new DeserializationException(msg, e);
        }
    }

    protected T readValue(byte[] bytes) throws IOException {
        return objectMapper.readValue(bytes, returnType);
    }
}

package io.jsonwebtoken.io;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @deprecated Please use io.jsonwebtoken.io.serializer.JacksonDeserializer instead.
 */
@Deprecated
public class JacksonDeserializer<T> extends io.jsonwebtoken.io.serializer.JacksonDeserializer<T> {

    public JacksonDeserializer() {
        super();
    }

    public JacksonDeserializer(ObjectMapper objectMapper) {
        super(objectMapper);
    }
}

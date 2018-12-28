package io.jsonwebtoken.io;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @deprecated Please use io.jsonwebtoken.io.serializer.JacksonSerializer instead.
 */
@Deprecated
public class JacksonSerializer<T> extends io.jsonwebtoken.io.serializer.JacksonSerializer<T> {

    public JacksonSerializer() {
        super();
    }

    public JacksonSerializer(ObjectMapper objectMapper) {
        super(objectMapper);
    }
}

package io.jsonwebtoken.jackson.io;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.jsonwebtoken.io.AbstractDeserializer;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.Map;

/**
 * Deserializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.10.0
 */
public class JacksonDeserializer<T> extends AbstractDeserializer<T> {

    private final Class<T> returnType;
    private final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for deserialization.
     */
    public JacksonDeserializer() {
        this(JacksonSerializer.DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new JacksonDeserializer where the values of the claims can be parsed into given types.
     * A common usage example is to parse custom User object out of a claim.
     *
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     */
    public JacksonDeserializer(Map<String, Class<?>> claimTypeMap) {
        this(new ObjectMapper());
        Assert.notNull(claimTypeMap, "Claim type map cannot be null.");
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Object.class, new ClaimTypeDeserializer(Collections.unmodifiableMap(claimTypeMap)));
        objectMapper.registerModule(module);
    }

    /**
     * Constructor using the specified Jackson {@link ObjectMapper}.
     *
     * @param objectMapper the ObjectMapper to use for deserialization.
     */
    @SuppressWarnings("unchecked")
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
    protected T doDeserialize(Reader reader) throws Exception {
        return objectMapper.readValue(reader, returnType);
    }
}

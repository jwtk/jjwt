/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.jackson.io;

import io.jsonwebtoken.io.AbstractDeserializer;
import io.jsonwebtoken.lang.Assert;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.deser.jdk.UntypedObjectDeserializer;
import tools.jackson.databind.module.SimpleModule;

import java.io.Reader;
import java.util.Collections;
import java.util.Map;

/**
 * Deserializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.14.0
 */
public class Jackson3Deserializer<T> extends AbstractDeserializer<T> {

    private final Class<T> returnType;

    private final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for deserialization.
     */
    public Jackson3Deserializer() {
        this(Jackson3Serializer.DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new JacksonDeserializer where the values of the claims can be parsed into given types. A common usage
     * example is to parse custom User object out of a claim, for example the claims:
     * <pre>{@code
     * {
     *     "issuer": "https://issuer.example.com",
     *     "user": {
     *         "firstName": "Jill",
     *         "lastName": "Coder"
     *     }
     * }}</pre>
     * Passing a map of {@code ["user": User.class]} to this constructor would result in the {@code user} claim being
     * transformed to an instance of your custom {@code User} class, instead of the default of {@code Map}.
     * <p>
     * Because custom type parsing requires modifying the state of a Jackson {@code ObjectMapper}, this
     * constructor creates a new internal {@code ObjectMapper} instance and customizes it to support the
     * specified {@code claimTypeMap}.  This ensures that the JJWT parsing behavior does not unexpectedly
     * modify the state of another application-specific {@code ObjectMapper}.
     * <p>
     * If you would like to use your own {@code ObjectMapper} instance that also supports custom types for
     * JWT {@code Claims}, you will need to first customize your {@code ObjectMapper} instance by registering
     * your custom types and then use the {@link #Jackson3Deserializer(ObjectMapper)} constructor instead.
     *
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     */
    public Jackson3Deserializer(Map<String, Class<?>> claimTypeMap) {
        // DO NOT specify JacksonSerializer.DEFAULT_OBJECT_MAPPER here as that would modify the shared instance
        this(Jackson3Serializer.newObjectMapper(), claimTypeMap);
    }

    /**
     * Deserializer using a Jackson {@link ObjectMapper}.
     *
     * @since 0.14.0
     * @param objectMapper
     */
    @SuppressWarnings("unchecked")
    public Jackson3Deserializer(ObjectMapper objectMapper) {
        this(objectMapper, (Class<T>) Object.class);
    }

    /**
     * Creates a new JacksonDeserializer where the values of the claims can be parsed into given types by registering
     * a type-converting {@link  tools.jackson.databind.JacksonModule Module} on the specified {@link ObjectMapper}.
     * A common usage example is to parse custom User object out of a claim, for example the claims:
     * <pre>{@code
     * {
     *     "issuer": "https://issuer.example.com",
     *     "user": {
     *         "firstName": "Jill",
     *         "lastName": "Coder"
     *     }
     * }}</pre>
     * Passing a map of {@code ["user": User.class]} to this constructor would result in the {@code user} claim being
     * transformed to an instance of your custom {@code User} class, instead of the default of {@code Map}.
     * <p>
     * Because custom type parsing requires modifying the state of a Jackson {@code ObjectMapper}, this
     * constructor modifies the specified {@code objectMapper} argument and customizes it to support the
     * specified {@code claimTypeMap}.
     * <p>
     * If you do not want your {@code ObjectMapper} instance modified, but also want to support custom types for
     * JWT {@code Claims}, you will need to first customize your {@code ObjectMapper} instance by registering
     * your custom types separately and then use the {@link #Jackson3Deserializer(ObjectMapper)} constructor instead
     * (which does not modify the {@code objectMapper} argument).
     *
     * @param objectMapper the objectMapper to modify by registering a custom type-converting
     *                     {@link tools.jackson.databind.JacksonModule Module}
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     */
    public Jackson3Deserializer(ObjectMapper objectMapper, Map<String, Class<?>> claimTypeMap) {
        this(objectMapper, (Class<T>) Object.class, claimTypeMap);
    }

    private Jackson3Deserializer(ObjectMapper objectMapper, Class<T> returnType) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.objectMapper = objectMapper;
        this.returnType = returnType;
    }

    /**
     *
     * @param objectMapper
     * @param returnType
     * @param claimTypeMap
     */
    private Jackson3Deserializer(ObjectMapper objectMapper, Class<T> returnType, Map<String, Class<?>> claimTypeMap) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        Assert.notNull(claimTypeMap, "Claim type map cannot be null.");
        // register a new Deserializer on the ObjectMapper instance:
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Object.class, new MappedTypeDeserializer(Collections.unmodifiableMap(claimTypeMap)));
        this.objectMapper = objectMapper.rebuild().addModule(module).build();
        this.returnType = returnType;
    }

    @Override
    protected T doDeserialize(Reader reader) throws Exception {
        return objectMapper.readValue(reader, returnType);
    }

    /**
     * A Jackson {@link tools.jackson.databind.deser.std.StdDeserializer JsonDeserializer}, that will convert claim
     * values to types based on {@code claimTypeMap}.
     */
    private static class MappedTypeDeserializer extends UntypedObjectDeserializer {

        private final Map<String, Class<?>> claimTypeMap;

        private MappedTypeDeserializer(Map<String, Class<?>> claimTypeMap) {
            super((JavaType) null, null);
            this.claimTypeMap = claimTypeMap;
        }

        @Override
        public Object deserialize(JsonParser parser, DeserializationContext context) throws JacksonException {
            // check if the current claim key is mapped, if so traverse it's value
            String name = parser.currentName();
            if (claimTypeMap != null && name != null && claimTypeMap.containsKey(name)) {
                Class<?> type = claimTypeMap.get(name);
                //noinspection resource
                JsonNode node = parser.readValueAsTree();
                return context.readTreeAsValue(node, type);
            }
            // otherwise default to super
            return super.deserialize(parser, context);
        }
    }
}

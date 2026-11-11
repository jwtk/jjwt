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
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.deser.jdk.UntypedObjectDeserializer;
import tools.jackson.databind.module.SimpleModule;

import java.io.Reader;
import java.util.Collections;
import java.util.Map;

/**
 * Deserializer using a Jackson 3 {@link ObjectMapper}.
 *
 * <p>As of 0.14.0 this class uses Jackson 3 ({@code tools.jackson}) and requires Java 17 or later.  The equivalent
 * Jackson 2 ({@code com.fasterxml.jackson}) implementation for Java 8 or later is
 * {@code io.jsonwebtoken.jackson2.io.JacksonDeserializer} in the {@code jjwt-jackson2} module.</p>
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
     * This constructor uses a copy of JJWT's default {@code ObjectMapper} that is customized to support the
     * specified {@code claimTypeMap}.
     * <p>
     * If you would like to use your own {@code ObjectMapper} configuration that also supports custom types for
     * JWT {@code Claims}, use the {@link #JacksonDeserializer(ObjectMapper, Map)} constructor instead.
     *
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     */
    public JacksonDeserializer(Map<String, Class<?>> claimTypeMap) {
        this(JacksonSerializer.DEFAULT_OBJECT_MAPPER, claimTypeMap);
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

    /**
     * Creates a new JacksonDeserializer where the values of the claims can be parsed into given types by registering
     * a type-converting {@link tools.jackson.databind.JacksonModule JacksonModule} on a copy of the specified
     * {@link ObjectMapper}.
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
     * Jackson 3 {@code ObjectMapper}s are immutable, so the specified {@code objectMapper} argument is never
     * modified: this deserializer instead uses a copy of it that is customized to support the specified
     * {@code claimTypeMap}.
     *
     * @param objectMapper the objectMapper whose configuration will be used, in addition to a custom type-converting
     *                     {@link tools.jackson.databind.JacksonModule JacksonModule}
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     * @since 0.13.0
     */
    public JacksonDeserializer(ObjectMapper objectMapper, Map<String, Class<?>> claimTypeMap) {
        this(withClaimTypes(objectMapper, claimTypeMap));
    }

    private JacksonDeserializer(ObjectMapper objectMapper, Class<T> returnType) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.objectMapper = objectMapper;
        this.returnType = returnType;
    }

    private static ObjectMapper withClaimTypes(ObjectMapper objectMapper, Map<String, Class<?>> claimTypeMap) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        Assert.notNull(claimTypeMap, "Claim type map cannot be null.");
        // register a new Deserializer on a copy of the ObjectMapper instance:
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Object.class, new MappedTypeDeserializer(Collections.unmodifiableMap(claimTypeMap)));
        return objectMapper.rebuild().addModule(module).build();
    }

    @Override
    protected T doDeserialize(Reader reader) throws Exception {
        return objectMapper.readValue(reader, returnType);
    }

    /**
     * A Jackson {@link tools.jackson.databind.ValueDeserializer ValueDeserializer}, that will convert claim
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
                return context.readTreeAsValue(context.readTree(parser), type);
            }
            // otherwise default to super
            return super.deserialize(parser, context);
        }
    }
}

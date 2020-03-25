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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

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
     * your custom types and then use the {@link #JacksonDeserializer(ObjectMapper)} constructor instead.
     * 
     * @param claimTypeMap The claim name-to-class map used to deserialize claims into the given type
     */
    public JacksonDeserializer(Map<String, Class> claimTypeMap) {
        // DO NOT reuse JacksonSerializer.DEFAULT_OBJECT_MAPPER as this could result in sharing the custom deserializer
        // between instances
        this(new ObjectMapper());
        Assert.notNull(claimTypeMap, "Claim type map cannot be null.");
        // register a new Deserializer
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Object.class, new MappedTypeDeserializer(Collections.unmodifiableMap(claimTypeMap)));
        objectMapper.registerModule(module);
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

    /**
     * A Jackson {@link com.fasterxml.jackson.databind.JsonDeserializer JsonDeserializer}, that will convert claim
     * values to types based on {@code claimTypeMap}.
     */
    private static class MappedTypeDeserializer extends UntypedObjectDeserializer {

        private final Map<String, Class> claimTypeMap;

        private MappedTypeDeserializer(Map<String, Class> claimTypeMap) {
            super(null, null);
            this.claimTypeMap = claimTypeMap;
        }

        @Override
        public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            // check if the current claim key is mapped, if so traverse it's value
            String name = parser.currentName();
            if (claimTypeMap != null && name != null && claimTypeMap.containsKey(name)) {
                Class type = claimTypeMap.get(name);
                return parser.readValueAsTree().traverse(parser.getCodec()).readValueAs(type);
            }
            // otherwise default to super
            return super.deserialize(parser, context);
        }
    }
}

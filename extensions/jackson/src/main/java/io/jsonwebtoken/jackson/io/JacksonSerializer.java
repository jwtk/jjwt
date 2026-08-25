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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.jsonwebtoken.io.AbstractSerializer;
import io.jsonwebtoken.lang.Assert;

import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Map;

/**
 * Serializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.10.0
 */
public class JacksonSerializer<T> extends AbstractSerializer<T> {

    static final String MODULE_ID = "jjwt-jackson";
    static final Module MODULE;

    static {
        SimpleModule module = new SimpleModule(MODULE_ID);
        module.addSerializer(JacksonConfidentialValueSerializer.INSTANCE);
        MODULE = module;
    }

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = newObjectMapper();

    /**
     * Creates and returns a new ObjectMapper with the {@code jjwt-jackson} module registered and
     * {@code JsonParser.Feature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     *
     * @return a new ObjectMapper with the {@code jjwt-jackson} module registered and
     * {@code JsonParser.Feature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     *
     * @since 0.12.4
     */
    // package protected on purpose, do not expose to the public API
    static ObjectMapper newObjectMapper() {
        return new ObjectMapper()
                .registerModule(MODULE)
                .configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION, true) // https://github.com/jwtk/jjwt/issues/877
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); // https://github.com/jwtk/jjwt/issues/893
    }

    protected final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    public JacksonSerializer() {
        this(DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper} for serialization.
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    public JacksonSerializer(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper.registerModule(MODULE);
    }

    @Override
    protected void doSerialize(T t, OutputStream out) throws Exception {
        Assert.notNull(out, "OutputStream cannot be null.");
        ObjectWriter writer = this.objectMapper.writer().without(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
        writer.writeValue(out, t instanceof Map ? toJsonNode((Map<?, ?>) t) : t);
    }

    /*
     * Map values are declared as Object to Jackson, so type information declared on a value's base type is not
     * included. Serializing each map value independently lets Jackson resolve any type information configured for its
     * runtime type while retaining the existing behavior for values without type information.
     */
    private JsonNode toJsonNode(Object value) {
        if (value == null) {
            return objectMapper.nullNode();
        }
        if (value instanceof Map) {
            ObjectNode node = objectMapper.createObjectNode();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                node.set(String.valueOf(entry.getKey()), toJsonNode(entry.getValue()));
            }
            return node;
        }
        if (value instanceof Iterable) {
            ArrayNode node = objectMapper.createArrayNode();
            for (Object element : (Iterable<?>) value) {
                node.add(toJsonNode(element));
            }
            return node;
        }
        if (value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
            ArrayNode node = objectMapper.createArrayNode();
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                node.add(toJsonNode(Array.get(value, i)));
            }
            return node;
        }
        return objectMapper.valueToTree(value);
    }
}

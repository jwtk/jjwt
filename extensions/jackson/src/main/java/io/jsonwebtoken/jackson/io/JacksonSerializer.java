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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;

/**
 * Serializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.10.0
 */
public class JacksonSerializer<T> implements Serializer<T> {

    static final String MODULE_ID = "jjwt-jackson";
    static final Module MODULE;

    static {
        SimpleModule module = new SimpleModule(MODULE_ID);
        module.addSerializer(JacksonSupplierSerializer.INSTANCE);
        MODULE = module;
    }

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper().registerModule(MODULE);

    private final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    @SuppressWarnings("unused") //used via reflection by RuntimeClasspathDeserializerLocator
    public JacksonSerializer() {
        this(DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper} for serialization.
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    @SuppressWarnings("WeakerAccess") //intended for end-users to use when providing a custom ObjectMapper
    public JacksonSerializer(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper.registerModule(MODULE);
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

    /**
     * Serializes the specified instance value to a byte array using the underlying Jackson {@link ObjectMapper}.
     *
     * @param t the instance to serialize to a byte array
     * @return the byte array serialization of the specified instance
     * @throws JsonProcessingException if there is a problem during serialization
     */
    @SuppressWarnings("WeakerAccess") //for testing
    protected byte[] writeValueAsBytes(T t) throws JsonProcessingException {
        return this.objectMapper.writeValueAsBytes(t);
    }
}

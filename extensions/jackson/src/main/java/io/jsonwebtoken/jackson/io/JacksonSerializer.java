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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/**
 * Serializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.10.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of {@link JacksonWriter}
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class JacksonSerializer<T> extends JacksonWriter<T> implements Serializer<T> {

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    public JacksonSerializer() {
        super();
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper} for serialization.
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    public JacksonSerializer(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    @SuppressWarnings("deprecation")
    @Override
    public byte[] serialize(T t) throws SerializationException {
        Assert.notNull(t, "Object to serialize cannot be null.");
        try {
            return writeValueAsBytes(t);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            String msg = "Unable to serialize object: " + e.getMessage();
            throw new SerializationException(msg, e);
        }
    }

    /**
     * Serializes the specified instance value to a byte array using the underlying Jackson {@link ObjectMapper}.
     *
     * @param t the instance to serialize to a byte array
     * @return the byte array serialization of the specified instance
     * @throws com.fasterxml.jackson.core.JsonProcessingException if there is a problem during serialization
     */
    protected byte[] writeValueAsBytes(T t) throws com.fasterxml.jackson.core.JsonProcessingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(256);
        try (OutputStreamWriter writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
            write(writer, t);
        } catch (Throwable ex) {
            String msg = "Unable to write value as bytes: " + ex.getMessage();
            throw new JsonProcessingException(msg, ex);
        }
        return baos.toByteArray();
    }

    private static class JsonProcessingException extends com.fasterxml.jackson.core.JsonProcessingException {
        protected JsonProcessingException(String msg, Throwable rootCause) {
            super(msg, rootCause);
        }
    }
}

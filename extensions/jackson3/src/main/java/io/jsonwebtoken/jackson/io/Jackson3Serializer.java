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

import io.jsonwebtoken.io.AbstractSerializer;
import io.jsonwebtoken.lang.Assert;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectWriter;
import tools.jackson.databind.module.SimpleModule;

import java.io.OutputStream;

import static tools.jackson.core.StreamWriteFeature.AUTO_CLOSE_TARGET;
import static tools.jackson.databind.json.JsonMapper.builder;

/**
 * Serializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.14.0
 */
public class Jackson3Serializer<T> extends AbstractSerializer<T> {

    static final String MODULE_ID = "jjwt-jackson3";
    static final JacksonModule MODULE;

    static {
        SimpleModule module = new SimpleModule(MODULE_ID);
        module.addSerializer(Jackson3SupplierSerializer.INSTANCE);
        MODULE = module;
    }

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = newObjectMapper();

    /**
     * Creates and returns a new ObjectMapper with the {@code jjwt-jackson3} module registered and
     * {@code JsonParser.Feature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     *
     * @return a new ObjectMapper with the {@code jjwt-jackson3} module registered and
     * {@code JsonParser.Feature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     *
     * @since 0.12.4
     */
    // package protected on purpose, do not expose to the public API
    static ObjectMapper newObjectMapper() {
        return builder().addModule(MODULE)
                .configure(StreamReadFeature.STRICT_DUPLICATE_DETECTION, true) // https://github.com/jwtk/jjwt/issues/877
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false) // https://github.com/jwtk/jjwt/issues/893
                .build();
    }

    protected final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    public Jackson3Serializer() {
        this(DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper} for serialization.
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    public Jackson3Serializer(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper.rebuild().addModule(MODULE).build();
    }

    @Override
    protected void doSerialize(T t, OutputStream out) throws Exception {
        Assert.notNull(out, "OutputStream cannot be null.");

        ObjectWriter writer = this.objectMapper.writer().without(AUTO_CLOSE_TARGET);
        writer.writeValue(out, t);
    }
}

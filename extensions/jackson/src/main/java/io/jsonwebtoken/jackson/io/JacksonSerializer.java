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
import tools.jackson.core.StreamWriteFeature;
import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectWriter;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

import java.io.OutputStream;

/**
 * Serializer using a Jackson 3 {@link ObjectMapper}.
 *
 * <p>As of 0.14.0 this class uses Jackson 3 ({@code tools.jackson}) and requires Java 17 or later.  The equivalent
 * Jackson 2 ({@code com.fasterxml.jackson}) implementation for Java 8 or later is
 * {@code io.jsonwebtoken.jackson2.io.JacksonSerializer} in the {@code jjwt-jackson2} module.</p>
 *
 * @since 0.10.0
 */
public class JacksonSerializer<T> extends AbstractSerializer<T> {

    static final String MODULE_ID = "jjwt-jackson";
    static final JacksonModule MODULE;

    static {
        SimpleModule module = new SimpleModule(MODULE_ID);
        module.addSerializer(JacksonConfidentialValueSerializer.INSTANCE);
        MODULE = module;
    }

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = newObjectMapper();

    /**
     * Creates and returns a new ObjectMapper with the {@code jjwt-jackson} module registered and
     * {@code StreamReadFeature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     *
     * <p>The JSON that JJWT writes and accepts must not change merely because the major version of Jackson did, so
     * the returned ObjectMapper otherwise retains Jackson 2's default behavior wherever Jackson 3 changed a default
     * that affects it (for example, {@code java.util.Date} values are still written as numeric timestamps).</p>
     *
     * @return a new ObjectMapper with the {@code jjwt-jackson} module registered and
     * {@code StreamReadFeature.STRICT_DUPLICATE_DETECTION} enabled (set to true) and
     * {@code DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES} disabled (set to false).
     * @since 0.12.4
     */
    // package protected on purpose, do not expose to the public API
    static ObjectMapper newObjectMapper() {
        return JsonMapper.builder()
                .configureForJackson2() // retain 2.x data-binding defaults, see JavaDoc above
                .disable(JsonWriteFeature.COMBINE_UNICODE_SURROGATES_IN_UTF8) // as above: 2.x writes these escaped
                .addModule(MODULE)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION) // https://github.com/jwtk/jjwt/issues/877
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES) // https://github.com/jwtk/jjwt/issues/893
                .build();
    }

    /**
     * The Jackson ObjectMapper instance to use during serialization.
     */
    protected final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    public JacksonSerializer() {
        this.objectMapper = DEFAULT_OBJECT_MAPPER; // already has the jjwt-jackson module registered
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper}'s configuration for
     * serialization.
     *
     * <p>Jackson 3 {@code ObjectMapper}s are immutable, so the specified instance is never modified.  This
     * serializer instead uses a copy of it that additionally has the {@code jjwt-jackson} module registered, which
     * is required to serialize JWKs with secret or private values.</p>
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    public JacksonSerializer(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper.rebuild().addModule(MODULE).build();
    }

    @Override
    protected void doSerialize(T t, OutputStream out) throws Exception {
        Assert.notNull(out, "OutputStream cannot be null.");
        ObjectWriter writer = this.objectMapper.writer().without(StreamWriteFeature.AUTO_CLOSE_TARGET);
        writer.writeValue(out, t);
    }
}

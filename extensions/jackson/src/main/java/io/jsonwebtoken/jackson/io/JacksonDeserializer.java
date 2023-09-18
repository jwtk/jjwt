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
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Deserializer using a Jackson {@link ObjectMapper}.
 *
 * @since 0.10.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of {@link JacksonReader}
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class JacksonDeserializer<T> extends JacksonReader<T> implements Deserializer<T> {

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for deserialization.
     */
    public JacksonDeserializer() {
        super();
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
    public JacksonDeserializer(Map<String, Class<?>> claimTypeMap) {
        super(claimTypeMap);
    }

    /**
     * Constructor using the specified Jackson {@link ObjectMapper}.
     *
     * @param objectMapper the ObjectMapper to use for deserialization.
     */
    public JacksonDeserializer(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    @SuppressWarnings("deprecation")
    @Override
    public T deserialize(byte[] bytes) throws DeserializationException {
        try {
            return readValue(bytes);
        } catch (IOException e) {
            String msg = "Unable to deserialize JSON bytes: " + e.getMessage();
            throw new DeserializationException(msg, e);
        }
    }

    /**
     * Converts the specified byte array value to the desired typed instance using the Jackson {@link ObjectMapper}.
     *
     * @param bytes the byte array value to convert
     * @return the desired typed instance
     * @throws IOException if there is a problem during reading or instance creation
     */
    protected T readValue(byte[] bytes) throws IOException {
        Assert.notNull(bytes, "byte array argument cannot be null.");
        Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8);
        try {
            return read(reader);
        } finally {
            Objects.nullSafeClose(reader);
        }
    }
}

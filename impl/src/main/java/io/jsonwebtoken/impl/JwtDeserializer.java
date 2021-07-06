/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.IOException;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.StandardCharsets;

/**
 * A {@link Deserializer} implementation that wraps another Deserializer implementation to add common JWT related
 * error handling.
 * @param <T> type of object to deserialize.
 * @since 0.11.3
 */
class JwtDeserializer<T> implements Deserializer<T> {

    static final String MALFORMED_ERROR = "Malformed JWT JSON: ";
    static final String MALFORMED_COMPLEX_ERROR = "Malformed or excessively complex JWT JSON. This could reflect a potential malicious JWT, please investigate the JWT source further. JSON: ";

    private final Deserializer<T> deserializer;

    JwtDeserializer(Deserializer<T> deserializer) {
        Assert.notNull(deserializer, "deserializer cannot be null.");
        this.deserializer = deserializer;
    }

    @Override
    public T deserialize(byte[] bytes) throws DeserializationException {
        try {
            return deserializer.deserialize(bytes);
        } catch (DeserializationException e) {
            throw new MalformedJwtException(MALFORMED_ERROR + new String(bytes, StandardCharsets.UTF_8), e);
        } catch (StackOverflowError e) {
            throw new IOException(MALFORMED_COMPLEX_ERROR + new String(bytes, StandardCharsets.UTF_8), e);
        }
    }
}

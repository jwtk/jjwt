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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Reader;
import io.jsonwebtoken.lang.Assert;

/**
 * Function that wraps a {@link Reader} to add JWT-related error handling.
 *
 * @param <T> type of object to deserialize.
 * @since 0.11.3
 */
public final class JwtDeserializer<T> implements Function<java.io.Reader, T> {

    static final String MALFORMED_ERROR = "Malformed %s JSON: %s";
    static final String MALFORMED_COMPLEX_ERROR = "Malformed or excessively complex %s JSON. This could reflect a " +
            "potential malicious JWT, please investigate the JWT source further. Cause: %s";

    private final Reader<T> reader;
    private final String name;

    public JwtDeserializer(Reader<T> reader, String name) {
        this.reader = Assert.notNull(reader, "reader cannot be null.");
        this.name = Assert.hasText(name, "name cannot be null or empty.");
    }

    @Override
    public T apply(java.io.Reader reader) {
        Assert.notNull(reader, "Reader argument cannot be null.");
        try {
            return this.reader.read(reader);
        } catch (StackOverflowError e) {
            String msg = String.format(MALFORMED_COMPLEX_ERROR, this.name, e.getMessage());
            throw new DeserializationException(msg, e);
        } catch (Throwable t) {
            String msg = String.format(MALFORMED_ERROR, this.name, t.getMessage());
            throw new MalformedJwtException(msg, t);
        }
    }
}

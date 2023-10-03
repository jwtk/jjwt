/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

/**
 * Convenient base class to use to implement {@link Deserializer}s, with subclasses only needing to implement
 * {@link #doDeserialize(Reader)}.
 *
 * @param <T> the type of object returned after deserialization
 * @since 0.12.0
 */
public abstract class AbstractDeserializer<T> implements Deserializer<T> {

    /**
     * EOF (End of File) marker, equal to {@code -1}.
     */
    protected static final int EOF = -1;

    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * Default constructor, does not initialize any internal state.
     */
    protected AbstractDeserializer() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final T deserialize(byte[] bytes) throws DeserializationException {
        bytes = bytes == null ? EMPTY_BYTES : bytes; // null safe
        InputStream in = new ByteArrayInputStream(bytes);
        Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
        return deserialize(reader);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final T deserialize(Reader reader) throws DeserializationException {
        Assert.notNull(reader, "Reader argument cannot be null.");
        try {
            return doDeserialize(reader);
        } catch (Throwable t) {
            if (t instanceof DeserializationException) {
                throw (DeserializationException) t;
            }
            String msg = "Unable to deserialize: " + t.getMessage();
            throw new DeserializationException(msg, t);
        }
    }

    /**
     * Reads the specified character stream and returns the corresponding Java object.
     *
     * @param reader the reader to use to read the character stream
     * @return the deserialized Java object
     * @throws Exception if there is a problem reading the stream or creating the expected Java object
     */
    protected abstract T doDeserialize(Reader reader) throws Exception;
}

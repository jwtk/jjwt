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

/**
 * Convenient base class to use to implement {@link Deserializer}s, with only the {@link #doDeserialize(InputStream)}.
 *
 * @param <T> the type of object returned after deserialization
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractDeserializer<T> implements Deserializer<T> {

    /**
     * EOF (End of File) marker, equal to {@code -1}.
     */
    protected static final int EOF = -1;

    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * {@inheritDoc}
     */
    @Override
    public final T deserialize(byte[] bytes) throws DeserializationException {
        bytes = bytes == null ? EMPTY_BYTES : bytes; // null safe
        return deserialize(new ByteArrayInputStream(bytes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final T deserialize(InputStream in) throws DeserializationException {
        Assert.notNull(in, "InputStream argument cannot be null.");
        try {
            return doDeserialize(in);
        } catch (Throwable t) {
            if (t instanceof DeserializationException) {
                throw (DeserializationException) t;
            }
            String msg = "Unable to deserialize: " + t.getMessage();
            throw new DeserializationException(msg, t);
        }
    }

    /**
     * Reads the specified {@code InputStream} and returns the corresponding Java object.
     *
     * @param in the input stream to read
     * @return the deserialized Java object
     * @throws DeserializationException if there is a problem reading the stream or creating the expected Java object
     */
    protected abstract T doDeserialize(InputStream in) throws Exception;
}

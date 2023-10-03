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

import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * Convenient base class to use to implement {@link Serializer}s, with subclasses only needing to implement
 * * {@link #doSerialize(Object, OutputStream)}.
 *
 * @param <T> the type of object to serialize
 * @since 0.12.0
 */
public abstract class AbstractSerializer<T> implements Serializer<T> {

    /**
     * Default constructor, does not initialize any internal state.
     */
    protected AbstractSerializer() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final byte[] serialize(T t) throws SerializationException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        serialize(t, out);
        return out.toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void serialize(T t, OutputStream out) throws SerializationException {
        try {
            doSerialize(t, out);
        } catch (Throwable e) {
            if (e instanceof SerializationException) {
                throw (SerializationException) e;
            }
            String msg = "Unable to serialize object of type " + Objects.nullSafeClassName(t) + ": " + e.getMessage();
            throw new SerializationException(msg, e);
        }
    }

    /**
     * Converts the specified Java object into a formatted data byte stream, writing the bytes to the specified
     * {@code out}put stream.
     *
     * @param t   the object to convert to a byte stream
     * @param out the stream to write to
     * @throws Exception if there is a problem converting the object to a byte stream or writing the
     *                   bytes to the {@code out}put stream.
     * @since 0.12.0
     */
    protected abstract void doSerialize(T t, OutputStream out) throws Exception;
}

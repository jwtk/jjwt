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
package io.jsonwebtoken.io;

import java.io.Reader;

/**
 * A {@code Deserializer} is able to convert serialized byte streams into Java objects.
 *
 * @param <T> the type of object to be returned as a result of deserialization.
 * @since 0.10.0
 */
public interface Deserializer<T> {

    /**
     * Convert the specified formatted data byte array into a Java object.
     *
     * @param bytes the formatted data byte array to convert
     * @return the reconstituted Java object
     * @throws DeserializationException if there is a problem converting the byte array to an object.
     * @deprecated since 0.12.0 in favor of {@link #deserialize(Reader)}
     */
    @Deprecated
    T deserialize(byte[] bytes) throws DeserializationException;

    /**
     * Reads the specified character stream and returns the corresponding Java object.
     *
     * @param reader the reader to use to read the character stream
     * @return the deserialized Java object
     * @throws DeserializationException if there is a problem reading the stream or creating the expected Java object
     * @since 0.12.0
     */
    T deserialize(Reader reader) throws DeserializationException;
}

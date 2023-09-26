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

import java.io.OutputStream;

/**
 * An encoder converts data of one type into another formatted data value.
 *
 * @param <T> the type of data to convert
 * @param <R> the type of the resulting formatted data
 * @since 0.10.0
 */
public interface Encoder<T, R> {

    /**
     * Convert the specified data into another formatted data value.
     *
     * @param t the data to convert
     * @return the resulting formatted data value
     * @throws EncodingException if there is a problem during encoding
     */
    R encode(T t) throws EncodingException;

    /**
     * Wraps the specified {@code OutputStream} to ensure any stream bytes are encoded.
     *
     * @param out the output stream to encode
     * @return a new output stream that will encode stream content
     */
    OutputStream encode(OutputStream out);
}

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

/**
 * A decoder converts an already-encoded data value to a desired data type.
 *
 * @since 0.10.0
 */
public interface Decoder<T, R> {

    /**
     * Convert the specified encoded data value into the desired data type.
     *
     * @param t the encoded data
     * @return the resulting expected data
     * @throws DecodingException if there is a problem during decoding.
     */
    R decode(T t) throws DecodingException;
}

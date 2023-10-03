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

import java.io.InputStream;
import java.io.Reader;

/**
 * A Parser converts a character stream into a Java object.
 *
 * @param <T> the instance type created after parsing
 * @since 0.12.0
 */
public interface Parser<T> {

    /**
     * Parse the specified character sequence into a Java object.
     *
     * @param input the character sequence to parse into a Java object.
     * @return the Java object represented by the specified {@code input} stream.
     */
    T parse(CharSequence input);

    /**
     * Parse the specified character sequence with the specified bounds into a Java object.
     *
     * @param input The character sequence, may be {@code null}
     * @param start The start index in the character sequence, inclusive
     * @param end   The end index in the character sequence, exclusive
     * @return the Java object represented by the specified sequence bounds
     * @throws IllegalArgumentException if the start index is negative, or if the end index is smaller than the start index
     */
    T parse(CharSequence input, int start, int end);

    /**
     * Parse the specified character sequence into a Java object.
     *
     * @param reader the reader to use to parse a Java object.
     * @return the Java object represented by the specified {@code input} stream.
     */
    T parse(Reader reader);

    /**
     * Parses the specified {@link InputStream} assuming {@link java.nio.charset.StandardCharsets#UTF_8 UTF_8} encoding.
     * This is a convenience alias for:
     *
     * <blockquote><pre>{@link #parse(Reader) parse}(new {@link java.io.InputStreamReader
     * InputStreamReader}(in, {@link java.nio.charset.StandardCharsets#UTF_8
     * StandardCharsets.UTF_8});</pre></blockquote>
     *
     * @param in the UTF-8 InputStream.
     * @return the Java object represented by the specified {@link InputStream}.
     */
    T parse(InputStream in);
}

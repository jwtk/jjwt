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

import java.io.IOException;

/**
 * A {@code Writer} writes an object to an output stream.
 *
 * @param <T> the type of object to write.
 * @since JJWT_RELEASE_VERSION
 */
public interface Writer<T> {

    /**
     * Writes {@code t} to the output stream, but does not close it; the caller must close the stream as necessary.
     *
     * @param out the output stream.
     * @param t   the object to write.
     * @throws IOException if there is a problem writing.
     */
    void write(java.io.Writer out, T t) throws IOException;
}

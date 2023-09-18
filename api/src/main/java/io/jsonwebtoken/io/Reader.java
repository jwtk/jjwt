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
 * A {@code Reader} reads an object from an input stream.
 *
 * @param <T> the type of object read.
 * @since JJWT_RELEASE_VERSION
 */
public interface Reader<T> {

    /**
     * Reads an object from an input stream, but does not close it; the caller must close the stream as necessary.
     *
     * @param in the input stream.
     * @return the object read from the stream.
     * @throws IOException if there is a problem reading from the stream or creating the expected object.
     */
    T read(java.io.Reader in) throws IOException;
}

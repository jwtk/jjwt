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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Compresses and decompresses byte streams.
 *
 * <p><b>&quot;zip&quot; identifier</b></p>
 *
 * <p>{@code CompressionAlgorithm} extends {@code Identifiable}; the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWT
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3"><code>zip</code></a> header value.</p>
 *
 * <p><b>Custom Implementations</b></p>
 *
 * <p>A custom implementation of this interface may be used when creating a JWT by calling the
 * {@link JwtBuilder#compressWith(CompressionAlgorithm)} method.</p>
 *
 * <p>To ensure that parsing is possible, the parser must be aware of the implementation by adding it to the
 * {@link JwtParserBuilder#zip()} collection during parser construction.</p>
 *
 * @see Jwts.ZIP#DEF
 * @see Jwts.ZIP#GZIP
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.3">JSON Web Encryption Compression Algorithms Registry</a>
 * @since 0.12.0
 */
public interface CompressionAlgorithm extends Identifiable {

    /**
     * Wraps the specified {@code OutputStream} to ensure any stream bytes are compressed as they are written.
     *
     * @param out the stream to wrap for compression
     * @return the stream to use for writing
     */
    OutputStream compress(OutputStream out);

    /**
     * Wraps the specified {@code InputStream} to ensure any stream bytes are decompressed as they are read.
     *
     * @param in the stream to wrap for decompression
     * @return the stream to use for reading
     */
    InputStream decompress(InputStream in);
}

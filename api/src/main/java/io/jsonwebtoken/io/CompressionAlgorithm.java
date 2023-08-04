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

import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.Jwts;

import java.util.Collection;

/**
 * Compresses and decompresses byte arrays.
 *
 * <p><b>&quot;zip&quot; identifier</b></p>
 *
 * <p>{@code CompressionAlgorithm} extends {@code Identifiable}; the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWT
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3"><code>zip</code></a> header value.</p>
 *
 * <p><b>Custom Implementations</b></p>
 * <p>A custom implementation of this interface may be used when creating a JWT by calling the
 * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionAlgorithm)} method.  To ensure that parsing is
 * possible, the parser must be aware of the implementation by calling
 * {@link io.jsonwebtoken.JwtParserBuilder#addCompressionAlgorithms(Collection)} during parser construction.</p>
 *
 * @see Jwts.ZIP#DEF
 * @see Jwts.ZIP#GZIP
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.3">JSON Web Encryption Compression Algorithms Registry</a>
 * @since JJWT_RELEASE_VERSION
 */
public interface CompressionAlgorithm extends Identifiable {

    /**
     * Compresses the specified byte array, returning the compressed byte array result.
     *
     * @param content bytes to compress
     * @return compressed bytes
     * @throws CompressionException if the specified byte array cannot be compressed.
     */
    byte[] compress(byte[] content) throws CompressionException;

    /**
     * Decompresses the specified compressed byte array, returning the decompressed byte array result.  The
     * specified byte array must already be in compressed form.
     *
     * @param compressed compressed bytes
     * @return decompressed bytes
     * @throws CompressionException if the specified byte array cannot be decompressed.
     */
    byte[] decompress(byte[] compressed) throws CompressionException;
}

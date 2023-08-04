/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken;

import io.jsonwebtoken.io.CompressionAlgorithm;

/**
 * Compresses and decompresses byte arrays according to a compression algorithm.
 *
 * <p><b>&quot;zip&quot; identifier</b></p>
 *
 * <p>{@code CompressionCodec} extends {@code Identifiable}; the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWT
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a> header value.</p>
 *
 * @see Jwts.ZIP#DEF
 * @see Jwts.ZIP#GZIP
 * @since 0.6.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of {@link io.jsonwebtoken.io.CompressionAlgorithm} to equal the RFC name for this concept.
 */
@Deprecated
public interface CompressionCodec extends CompressionAlgorithm {

    /**
     * The algorithm name to use as the JWT
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a> header value.
     *
     * @return the algorithm name to use as the JWT
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a> header value.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getId()} to ensure congruence with
     * all other identifiable algorithms.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    String getAlgorithmName();
}
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
package io.jsonwebtoken;

/**
 * Provides default implementations of the {@link CompressionCodec} interface.
 *
 * @see Jwts.ZIP#DEF
 * @see Jwts.ZIP#GZIP
 * @since 0.7.0
 * @deprecated in favor of {@link Jwts.ZIP}.
 */
@Deprecated //TODO: delete for 1.0
public final class CompressionCodecs {

    private CompressionCodecs() {
    } //prevent external instantiation

    /**
     * Codec implementing the <a href="https://tools.ietf.org/html/rfc7518">JWA</a> standard
     * <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate</a> compression algorithm
     *
     * @deprecated in favor of {@link Jwts.ZIP#DEF}.
     */
    @Deprecated
    public static final CompressionCodec DEFLATE = (CompressionCodec) Jwts.ZIP.DEF;

    /**
     * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a> compression algorithm.
     *
     * <p><b>Compatibility Warning</b></p>
     *
     * <p><b>This is not a standard JWA compression algorithm</b>.  Be sure to use this only when you are confident
     * that all parties accessing the token support the gzip algorithm.</p>
     *
     * <p>If you're concerned about compatibility, the {@link Jwts.ZIP#DEF DEF} code is JWA standards-compliant.</p>
     *
     * @deprecated in favor of {@link Jwts.ZIP#GZIP}
     */
    @Deprecated
    public static final CompressionCodec GZIP = (CompressionCodec) Jwts.ZIP.GZIP;

}

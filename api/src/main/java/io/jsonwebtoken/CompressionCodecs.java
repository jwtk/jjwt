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

import io.jsonwebtoken.lang.Classes;

/**
 * Provides default implementations of the {@link CompressionCodec} interface.
 *
 * @see #DEFLATE
 * @see #GZIP
 * @since 0.7.0
 */
public final class CompressionCodecs {

    private CompressionCodecs() {
    } //prevent external instantiation

    /**
     * Codec implementing the <a href="https://tools.ietf.org/html/rfc7518">JWA</a> standard
     * <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate</a> compression algorithm
     */
    public static final CompressionCodec DEFLATE =
        Classes.newInstance("io.jsonwebtoken.impl.compression.DeflateCompressionCodec");

    /**
     * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a> compression algorithm.
     * <h3>Compatibility Warning</h3>
     * <p><b>This is not a standard JWA compression algorithm</b>.  Be sure to use this only when you are confident
     * that all parties accessing the token support the gzip algorithm.</p>
     * <p>If you're concerned about compatibility, the {@link #DEFLATE DEFLATE} code is JWA standards-compliant.</p>
     */
    public static final CompressionCodec GZIP =
        Classes.newInstance("io.jsonwebtoken.impl.compression.GzipCompressionCodec");

}

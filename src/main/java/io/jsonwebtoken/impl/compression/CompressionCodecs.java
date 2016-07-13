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
package io.jsonwebtoken.impl.compression;

import io.jsonwebtoken.CompressionCodec;

/**
 * Provides default implementations of the {@link CompressionCodec} interface.
 *
 * @see #DEFLATE
 * @see #GZIP
 *
 * @since 0.6.0
 * @deprecated use {@link io.jsonwebtoken.CompressionCodecs} instead.
 */
@Deprecated
public final class CompressionCodecs {

    private static final CompressionCodecs I = new CompressionCodecs();

    private CompressionCodecs(){} //prevent external instantiation

    /**
     * Codec implementing the <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate</a> compression algorithm
     * @deprecated use {@link io.jsonwebtoken.CompressionCodecs#DEFLATE} instead.
     */
    @Deprecated
    public static final CompressionCodec DEFLATE = io.jsonwebtoken.CompressionCodecs.DEFLATE;

    /**
     * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a> compression algorithm
     * @deprecated use {@link io.jsonwebtoken.CompressionCodecs#GZIP} instead.
     */
    @Deprecated
    public static final CompressionCodec GZIP = io.jsonwebtoken.CompressionCodecs.GZIP;

}

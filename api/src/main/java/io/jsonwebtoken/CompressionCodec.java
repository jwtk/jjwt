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

/**
 * Compresses and decompresses byte arrays according to a compression algorithm.
 *
 * @see CompressionCodecs#DEFLATE
 * @see CompressionCodecs#GZIP
 * @since 0.6.0
 */
public interface CompressionCodec {

    /**
     * The compression algorithm name to use as the JWT's {@code zip} header value.
     *
     * @return the compression algorithm name to use as the JWT's {@code zip} header value.
     */
    String getAlgorithmName();

    /**
     * Compresses the specified byte array according to the compression {@link #getAlgorithmName() algorithm}.
     *
     * @param payload bytes to compress
     * @return compressed bytes
     * @throws CompressionException if the specified byte array cannot be compressed according to the compression
     *                              {@link #getAlgorithmName() algorithm}.
     */
    byte[] compress(byte[] payload) throws CompressionException;

    /**
     * Decompresses the specified compressed byte array according to the compression
     * {@link #getAlgorithmName() algorithm}.  The specified byte array must already be in compressed form
     * according to the {@link #getAlgorithmName() algorithm}.
     *
     * @param compressed compressed bytes
     * @return decompressed bytes
     * @throws CompressionException if the specified byte array cannot be decompressed according to the compression
     *                              {@link #getAlgorithmName() algorithm}.
     */
    byte[] decompress(byte[] compressed) throws CompressionException;
}
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
 * Defines how to compress and decompress byte arrays.
 *
 * @since 0.5.2
 */
public interface CompressionCodec {

    /**
     * The algorithm name that would appear in the JWT header.
     * @return the algorithm name that would appear in the JWT header
     */
    String getAlgorithmName();

    /**
     * Takes a byte array and returns a compressed version.
     * @param payload bytes to compress
     * @return compressed bytes
     */
    byte[] compress(byte[] payload);

    /**
     * Takes a compressed byte array and returns a decompressed version.
     * @param compressed compressed bytes
     * @return decompressed bytes
     */
    byte[] decompress(byte[] compressed);
}
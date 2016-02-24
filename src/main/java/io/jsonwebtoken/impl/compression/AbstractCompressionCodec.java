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
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;

/**
 * Abstract class that asserts arguments and wraps IOException with CompressionException.
 *
 * @since 0.6.0
 */
public abstract class AbstractCompressionCodec implements CompressionCodec {

    /**
     * Implement this method to do the actual work of compressing the payload
     *
     * @param payload the bytes to compress
     * @return the compressed bytes
     * @throws IOException if the compression causes an IOException
     */
    protected abstract byte[] doCompress(byte[] payload) throws IOException;

    /**
     * Asserts that payload is not null and calls {@link #doCompress(byte[]) doCompress}
     *
     * @param payload bytes to compress
     * @return compressed bytes
     * @throws CompressionException if {@link #doCompress(byte[]) doCompress} throws an IOException
     */
    @Override
    public final byte[] compress(byte[] payload) {
        Assert.notNull(payload, "payload cannot be null.");

        try {
            return doCompress(payload);
        } catch (IOException e) {
            throw new CompressionException("Unable to compress payload.", e);
        }
    }

    /**
     * Asserts the compressed bytes is not null and calls {@link #doDecompress(byte[]) doDecompress}
     *
     * @param compressed compressed bytes
     * @return decompressed bytes
     * @throws CompressionException if {@link #doDecompress(byte[]) doDecompress} throws an IOException
     */
    @Override
    public final byte[] decompress(byte[] compressed) {
        Assert.notNull(compressed, "compressed bytes cannot be null.");

        try {
            return doDecompress(compressed);
        } catch (IOException e) {
            throw new CompressionException("Unable to decompress bytes.", e);
        }
    }

    /**
     * Implement this method to do the actual work of decompressing the compressed bytes.
     *
     * @param compressed compressed bytes
     * @return decompressed bytes
     * @throws IOException if the decompression runs into an IO problem
     */
    protected abstract byte[] doDecompress(byte[] compressed) throws IOException;
}

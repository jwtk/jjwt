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
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Abstract class that asserts arguments and wraps IOException with CompressionException.
 *
 * @since 0.6.0
 */
public abstract class AbstractCompressionCodec implements CompressionCodec {

    //package-protected for a point release.  This can be made protected on a minor release (0.11.0, 0.12.0, 1.0, etc).
    //TODO: make protected on a minor release
    interface StreamWrapper {
        OutputStream wrap(OutputStream out) throws IOException;
    }

    //package-protected for a point release.  This can be made protected on a minor release (0.11.0, 0.12.0, 1.0, etc).
    //TODO: make protected on a minor release
    byte[] readAndClose(InputStream input) throws IOException {
        byte[] buffer = new byte[512];
        ByteArrayOutputStream out = new ByteArrayOutputStream(buffer.length);
        int read;
        try {
            read = input.read(buffer); //assignment separate from loop invariant check for code coverage checks
            while (read != -1) {
                out.write(buffer, 0, read);
                read = input.read(buffer);
            }
        } finally {
            Objects.nullSafeClose(input);
        }
        return out.toByteArray();
    }

    //package-protected for a point release.  This can be made protected on a minor release (0.11.0, 0.12.0, 1.0, etc).
    //TODO: make protected on a minor release
    byte[] writeAndClose(byte[] payload, StreamWrapper wrapper) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(512);
        OutputStream compressionStream = wrapper.wrap(outputStream);
        try {
            compressionStream.write(payload);
            compressionStream.flush();
        } finally {
            Objects.nullSafeClose(compressionStream);
        }
        return outputStream.toByteArray();
    }

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

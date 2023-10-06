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
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.PropagatingExceptionFunction;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Abstract class that asserts arguments and wraps IOException with CompressionException.
 *
 * @since 0.6.0
 */
@SuppressWarnings("deprecation")
public abstract class AbstractCompressionAlgorithm implements CompressionAlgorithm, CompressionCodec {

    private static <T, R> Function<T, R> propagate(CheckedFunction<T, R> fn, String msg) {
        return new PropagatingExceptionFunction<>(fn, CompressionException.class, msg);
    }

    private static <T, R> Function<T, R> forCompression(CheckedFunction<T, R> fn) {
        return propagate(fn, "Compression failed.");
    }

    private static <T, R> Function<T, R> forDecompression(CheckedFunction<T, R> fn) {
        return propagate(fn, "Decompression failed.");
    }

    private final String id;
    private final Function<OutputStream, OutputStream> OS_WRAP_FN;
    private final Function<InputStream, InputStream> IS_WRAP_FN;
    private final Function<byte[], byte[]> COMPRESS_FN;

    private final Function<byte[], byte[]> DECOMPRESS_FN;

    protected AbstractCompressionAlgorithm(String id) {
        this.id = Assert.hasText(Strings.clean(id), "id argument cannot be null or empty.");
        this.OS_WRAP_FN = forCompression(new CheckedFunction<OutputStream, OutputStream>() {
            @Override
            public OutputStream apply(OutputStream out) throws Exception {
                return doCompress(out);
            }
        });
        this.COMPRESS_FN = forCompression(new CheckedFunction<byte[], byte[]>() {
            @Override
            public byte[] apply(byte[] data) throws Exception {
                return doCompress(data);
            }
        });
        this.IS_WRAP_FN = forDecompression(new CheckedFunction<InputStream, InputStream>() {
            @Override
            public InputStream apply(InputStream is) throws Exception {
                return doDecompress(is);
            }
        });
        this.DECOMPRESS_FN = forDecompression(new CheckedFunction<byte[], byte[]>() {
            @Override
            public byte[] apply(byte[] data) throws Exception {
                return doDecompress(data);
            }
        });
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getAlgorithmName() {
        return getId();
    }

    @Override
    public final OutputStream compress(final OutputStream out) throws CompressionException {
        return OS_WRAP_FN.apply(out);
    }

    protected abstract OutputStream doCompress(OutputStream out) throws IOException;

    @Override
    public final InputStream decompress(InputStream is) throws CompressionException {
        return IS_WRAP_FN.apply(is);
    }

    protected abstract InputStream doDecompress(InputStream is) throws IOException;

    @Override
    public final byte[] compress(byte[] content) {
        if (Bytes.isEmpty(content)) return Bytes.EMPTY;
        return this.COMPRESS_FN.apply(content);
    }

    private byte[] doCompress(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        OutputStream compression = compress(out);
        try {
            compression.write(data);
            compression.flush();
        } finally {
            Objects.nullSafeClose(compression);
        }
        return out.toByteArray();
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
        if (Bytes.isEmpty(compressed)) return Bytes.EMPTY;
        return this.DECOMPRESS_FN.apply(compressed);
    }

    /**
     * Implement this method to do the actual work of decompressing the compressed bytes.
     *
     * @param compressed compressed bytes
     * @return decompressed bytes
     * @throws IOException if the decompression runs into an IO problem
     */
    protected byte[] doDecompress(byte[] compressed) throws IOException {
        InputStream is = Streams.of(compressed);
        InputStream decompress = decompress(is);
        byte[] buffer = new byte[512];
        ByteArrayOutputStream out = new ByteArrayOutputStream(buffer.length);
        int read = 0;
        try {
            while (read != Streams.EOF) {
                read = decompress.read(buffer); //assignment separate from loop invariant check for code coverage checks
                if (read > 0) out.write(buffer, 0, read);
            }
        } finally {
            Objects.nullSafeClose(decompress);
        }
        return out.toByteArray();
    }
}

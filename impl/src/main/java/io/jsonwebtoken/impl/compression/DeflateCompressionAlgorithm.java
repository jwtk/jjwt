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

import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Codec implementing the <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate compression algorithm</a>.
 *
 * @since 0.6.0
 */
public class DeflateCompressionAlgorithm extends AbstractCompressionAlgorithm {

    private static final String ID = "DEF";

    public DeflateCompressionAlgorithm() {
        super(ID);
    }

    @Override
    protected OutputStream doCompress(OutputStream out) {
        return new DeflaterOutputStream(out);
    }

    @Override
    protected InputStream doDecompress(InputStream is) {
        return new InflaterInputStream(is);
    }

    @Override
    protected byte[] doDecompress(final byte[] compressed) throws IOException {
        try {
            return super.doDecompress(compressed);
        } catch (IOException e1) {
            try {
                return doDecompressBackCompat(compressed);
            } catch (IOException e2) {
                throw e1; //retain/report original exception
            }
        }
    }

    /**
     * This implementation was in 0.10.6 and earlier - it will be used as a fallback for backwards compatibility if
     * {@link #doDecompress(byte[])} fails per <a href="https://github.com/jwtk/jjwt/issues/536">Issue 536</a>.
     *
     * @param compressed the compressed byte array
     * @return decompressed bytes
     * @throws IOException if unable to decompress using the 0.10.6 and earlier logic
     * @since 0.10.8
     */
    // package protected on purpose
    byte[] doDecompressBackCompat(byte[] compressed) throws IOException {
        InflaterOutputStream inflaterOutputStream = null;
        ByteArrayOutputStream decompressedOutputStream = null;

        try {
            decompressedOutputStream = new ByteArrayOutputStream();
            inflaterOutputStream = new InflaterOutputStream(decompressedOutputStream);
            inflaterOutputStream.write(compressed);
            inflaterOutputStream.flush();
            return decompressedOutputStream.toByteArray();
        } finally {
            Objects.nullSafeClose(decompressedOutputStream, inflaterOutputStream);
        }
    }
}

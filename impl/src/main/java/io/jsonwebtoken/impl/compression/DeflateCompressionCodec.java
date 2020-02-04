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

import java.io.ByteArrayInputStream;
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
public class DeflateCompressionCodec extends AbstractCompressionCodec {

    private static final String DEFLATE = "DEF";

    private static final StreamWrapper WRAPPER = new StreamWrapper() {
        @Override
        public OutputStream wrap(OutputStream out) {
            return new DeflaterOutputStream(out);
        }
    };

    @Override
    public String getAlgorithmName() {
        return DEFLATE;
    }

    @Override
    protected byte[] doCompress(byte[] payload) throws IOException {
        return writeAndClose(payload, WRAPPER);
    }

    @Override
    protected byte[] doDecompress(final byte[] compressed) throws IOException {
        try {
            return readAndClose(new InflaterInputStream(new ByteArrayInputStream(compressed)));
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
     * {@link #readAndClose(InputStream)} fails per <a href="https://github.com/jwtk/jjwt/issues/536">Issue 536</a>.
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

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
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip compression algorithm</a>.
 *
 * @since 0.6.0
 */
public class GzipCompressionCodec extends AbstractCompressionCodec implements CompressionCodec {

    private static final String GZIP = "GZIP";

    @Override
    public String getAlgorithmName() {
        return GZIP;
    }

    @Override
    protected byte[] doDecompress(byte[] compressed) throws IOException {
        byte[] buffer = new byte[512];

        ByteArrayOutputStream outputStream = null;
        GZIPInputStream gzipInputStream = null;
        ByteArrayInputStream inputStream = null;

        try {
            inputStream = new ByteArrayInputStream(compressed);
            gzipInputStream = new GZIPInputStream(inputStream);
            outputStream = new ByteArrayOutputStream();
            int read = gzipInputStream.read(buffer);
            while (read != -1) {
                outputStream.write(buffer, 0, read);
                read = gzipInputStream.read(buffer);
            }
            return outputStream.toByteArray();
        } finally {
            Objects.nullSafeClose(inputStream, gzipInputStream, outputStream);
        }
    }

    protected byte[] doCompress(byte[] payload) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        GZIPOutputStream compressorOutputStream = new GZIPOutputStream(outputStream, true);
        try {
            compressorOutputStream.write(payload, 0, payload.length);
            compressorOutputStream.finish();
            return outputStream.toByteArray();
        } finally {
            Objects.nullSafeClose(compressorOutputStream, outputStream);
        }
    }
}

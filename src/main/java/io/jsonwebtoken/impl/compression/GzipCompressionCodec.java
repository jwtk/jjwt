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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * GzipCompressionCodec
 *
 * @since 0.5.2
 */
public class GzipCompressionCodec implements CompressionCodec {

    private static final String GZIP = "GZIP";

    @Override
    public String getAlgorithmName() {
        return GZIP;
    }

    @Override
    public byte[] compress(byte[] payload) {
        Assert.notNull(payload, "payload cannot be null.");

        ByteArrayOutputStream outputStream = null;
        GZIPOutputStream gzipOutputStream = null;

        try {
            outputStream = new ByteArrayOutputStream();
            gzipOutputStream = new GZIPOutputStream(outputStream, true);
            gzipOutputStream.write(payload, 0, payload.length);
            gzipOutputStream.finish();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new CompressionException("Unable to compress payload.", e);
        } finally {
            Objects.nullSafeClose(outputStream, gzipOutputStream);
        }
    }

    @Override
    public byte[] decompress(byte[] compressed) {
        Assert.notNull(compressed, "compressed cannot be null.");

        byte[] buffer = new byte[512];

        ByteArrayOutputStream outputStream = null;
        GZIPInputStream gzipInputStream = null;
        ByteArrayInputStream inputStream = null;

        try {
            inputStream = new ByteArrayInputStream(compressed);
            gzipInputStream = new GZIPInputStream(inputStream);
            outputStream = new ByteArrayOutputStream();
            int read;
            while ((read = gzipInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
            }
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new CompressionException("Unable to decompress compressed payload.", e);
        } finally {
            Objects.nullSafeClose(inputStream, gzipInputStream, outputStream);
        }
    }
}

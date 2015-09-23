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
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

/**
 * DeflateCompressionCodec
 *
 * @since 0.5.2
 */
public class DeflateCompressionCodec implements CompressionCodec {

    private static final String DEFLATE = "DEF";

    @Override
    public String getAlgorithmName() {
        return DEFLATE;
    }

    @Override
    public byte[] compress(byte[] payload) {
        Assert.notNull(payload, "payload cannot be null.");

        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);

        ByteArrayOutputStream outputStream = null;
        DeflaterOutputStream deflaterOutputStream = null;
        try {
            outputStream = new ByteArrayOutputStream();
            deflaterOutputStream = new DeflaterOutputStream(outputStream, deflater, true);

            deflaterOutputStream.write(payload, 0, payload.length);
            deflaterOutputStream.flush();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new CompressionException("Unable to compress payload.", e);
        } finally {
            Objects.nullSafeClose(outputStream, deflaterOutputStream);
        }
    }

    @Override
    public byte[] decompress(byte[] compressed) {
        Assert.notNull(compressed, "compressed cannot be null.");

        InflaterOutputStream inflaterOutputStream = null;
        ByteArrayOutputStream decompressedOutputStream = null;

        try {
            decompressedOutputStream = new ByteArrayOutputStream();
            inflaterOutputStream = new InflaterOutputStream(decompressedOutputStream);
            inflaterOutputStream.write(compressed);
            inflaterOutputStream.flush();
            return decompressedOutputStream.toByteArray();
        } catch (IOException e) {
            throw new CompressionException("Unable to decompress compressed payload.", e);
        } finally {
            Objects.nullSafeClose(decompressedOutputStream, inflaterOutputStream);
        }
    }
}

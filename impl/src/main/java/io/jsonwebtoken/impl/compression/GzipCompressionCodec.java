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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip compression algorithm</a>.
 *
 * @since 0.6.0
 */
public class GzipCompressionCodec extends AbstractCompressionCodec implements CompressionCodec {

    private static final String GZIP = "GZIP";

    private static final StreamWrapper WRAPPER = new StreamWrapper() {
        @Override
        public OutputStream wrap(OutputStream out) throws IOException {
            return new GZIPOutputStream(out);
        }
    };

    @Override
    public String getAlgorithmName() {
        return GZIP;
    }

    @Override
    protected byte[] doCompress(byte[] payload) throws IOException {
        return writeAndClose(payload, WRAPPER);
    }

    @Override
    protected byte[] doDecompress(byte[] compressed) throws IOException {
        return readAndClose(new GZIPInputStream(new ByteArrayInputStream(compressed)));
    }
}

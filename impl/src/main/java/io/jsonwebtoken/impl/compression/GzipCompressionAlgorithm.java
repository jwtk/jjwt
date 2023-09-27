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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip compression algorithm</a>.
 *
 * @since 0.6.0
 */
public class GzipCompressionAlgorithm extends AbstractCompressionAlgorithm {

    private static final String ID = "GZIP";

    public GzipCompressionAlgorithm() {
        super(ID);
    }

    @Override
    protected OutputStream doCompress(OutputStream out) throws IOException {
        return new GZIPOutputStream(out);
    }

    @Override
    protected InputStream doDecompress(InputStream is) throws IOException {
        return new GZIPInputStream(is);
    }
}

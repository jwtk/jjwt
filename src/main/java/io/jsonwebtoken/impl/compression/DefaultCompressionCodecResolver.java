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
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

/**
 * Default implementation of {@link CompressionCodecResolver}.  This implementation will resolve DEF to
 * {@link DeflateCompressionCodec} and GZIP to {@link GzipCompressionCodec}.
 *
 * @since 0.5.2
 */
public class DefaultCompressionCodecResolver implements CompressionCodecResolver {

    @Override
    public CompressionCodec resolveCompressionCodec(Header header) {
        String cmpAlg = getAlgorithmFromHeader(header);

        final boolean hasCompressionAlgorithm = Strings.hasText(cmpAlg);
        if (!hasCompressionAlgorithm) {
            return null;
        }
        if (CompressionCodecs.DEFLATE.getAlgorithmName().equalsIgnoreCase(cmpAlg)) {
            return CompressionCodecs.DEFLATE;
        }
        if (CompressionCodecs.GZIP.getAlgorithmName().equalsIgnoreCase(cmpAlg)) {
            return CompressionCodecs.GZIP;
        }

        throw new CompressionException("Unsupported compression algorithm '" + cmpAlg + "'");
    }

    protected final String getAlgorithmFromHeader(Header header) {
        Assert.notNull(header, "header cannot be null.");

        return header.getCompressionAlgorithm();
    }
}

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
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.lang.Strings;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link CompressionCodecResolver} that supports the following:
 * <p>
 * <ul>
 * <li>If the specified JWT {@link Header} does not have a {@code zip} header, this implementation does
 * nothing and returns {@code null} to the caller, indicating no compression was used.</li>
 * <li>If the header has a {@code zip} value of {@code DEF}, a {@link DeflateCompressionCodec} will be returned.</li>
 * <li>If the header has a {@code zip} value of {@code GZIP}, a {@link GzipCompressionCodec} will be returned.</li>
 * <li>If the header has any other {@code zip} value, a {@link CompressionException} is thrown to reflect an
 * unrecognized algorithm.</li>
 * </ul>
 *
 * <p>If you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you must implement your own
 * {@link CompressionCodecResolver} and specify that when
 * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} and
 * {@link io.jsonwebtoken.JwtParser#setCompressionCodecResolver(CompressionCodecResolver) parsing} JWTs.</p>
 *
 * @see DeflateCompressionCodec
 * @see GzipCompressionCodec
 * @since 0.6.0
 */
public class DefaultCompressionCodecResolver implements CompressionCodecResolver {

    private static final String MISSING_COMPRESSION_MESSAGE = "Unable to find an implementation for compression algorithm [%s] using java.util.ServiceLoader. Ensure you include a backing implementation .jar in the classpath, for example jjwt-impl.jar, or your own .jar for custom implementations.";

    private final Map<String, CompressionCodec> codecs;

    public DefaultCompressionCodecResolver() {
        Map<String, CompressionCodec> codecMap = new HashMap<>();
        for (CompressionCodec codec : Services.loadAll(CompressionCodec.class)) {
            codecMap.put(codec.getAlgorithmName().toUpperCase(), codec);
        }

        codecMap.put(CompressionCodecs.DEFLATE.getAlgorithmName().toUpperCase(), CompressionCodecs.DEFLATE);
        codecMap.put(CompressionCodecs.GZIP.getAlgorithmName().toUpperCase(), CompressionCodecs.GZIP);

        codecs = Collections.unmodifiableMap(codecMap);
    }

    @Override
    public CompressionCodec resolveCompressionCodec(Header header) {
        String cmpAlg = getAlgorithmFromHeader(header);

        final boolean hasCompressionAlgorithm = Strings.hasText(cmpAlg);

        if (!hasCompressionAlgorithm) {
            return null;
        }
        return byName(cmpAlg);
    }

    private String getAlgorithmFromHeader(Header header) {
        Assert.notNull(header, "header cannot be null.");

        return header.getCompressionAlgorithm();
    }

    private CompressionCodec byName(String name) {
        Assert.hasText(name, "'name' must not be empty");

        CompressionCodec codec = codecs.get(name.toUpperCase());
        if (codec == null) {
            throw new CompressionException(String.format(MISSING_COMPRESSION_MESSAGE, name));
        }

        return codec;
    }
}

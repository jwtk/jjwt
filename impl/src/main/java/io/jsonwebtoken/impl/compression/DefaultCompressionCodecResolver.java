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
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Default implementation of {@link CompressionCodecResolver} that supports the following:
 *
 * <ul>
 * <li>If the specified JWT {@link Header} does not have a {@code zip} header, this implementation does
 * nothing and returns {@code null} to the caller, indicating no compression was used.</li>
 * <li>If the header has a {@code zip} value of {@code DEF}, a {@link DeflateCompressionCodec} will be returned.</li>
 * <li>If the header has a {@code zip} value of {@code GZIP}, a {@link GzipCompressionCodec} will be returned.</li>
 * <li>If the header has any other {@code zip} value, it tries to find corresponding {@code CompressionCodec} that
 * matches that {@link CompressionCodec#getId() id}. If it finds a match, it returns it.</li>
 * <li>If a matching {@code CompressionCodec} is not found for the specified {@code zip} value,
 * a {@link CompressionException} is thrown to reflect an unrecognized algorithm.</li>
 * </ul>
 *
 * <p>If you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you must implement your own
 * {@link CompressionCodecResolver} and specify that when
 * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} and
 * {@link io.jsonwebtoken.JwtParserBuilder#setCompressionCodecResolver(CompressionCodecResolver) parsing} JWTs.</p>
 *
 * @see DeflateCompressionCodec
 * @see GzipCompressionCodec
 * @since 0.6.0
 */
public class DefaultCompressionCodecResolver implements CompressionCodecResolver, Locator<CompressionCodec> {

    private static final String MISSING_COMPRESSION_MESSAGE = "Unable to find an implementation for compression " +
            "algorithm [%s] using java.util.ServiceLoader or via any specified extra CompressionCodec instances. " +
            "Ensure you include a backing implementation .jar in the classpath, for example jjwt-impl.jar, or " +
            "your own .jar for custom implementations, or use the JwtParser.addCompressionCodecs configuration " +
            "method.";

    private final Registry<String, CompressionCodec> codecs;

    public DefaultCompressionCodecResolver() {
        this(Collections.<CompressionCodec>emptySet());
    }

    public DefaultCompressionCodecResolver(Collection<CompressionCodec> extraCodecs) {
        Assert.notNull(extraCodecs, "extraCodecs cannot be null.");
        Set<CompressionCodec> codecs = new LinkedHashSet<>(Services.loadAll(CompressionCodec.class));
        codecs.addAll(extraCodecs);
        codecs.add(CompressionCodecs.DEFLATE); // standard ones are added last so they can't be accidentally replaced
        codecs.add(CompressionCodecs.GZIP);
        this.codecs = new IdRegistry<>(codecs);
    }

    @Override
    public CompressionCodec locate(Header<?> header) {
        Assert.notNull(header, "Header cannot be null.");
        String id = header.getCompressionAlgorithm();
        if (!Strings.hasText(id)) {
            return null;
        }
        CompressionCodec codec = codecs.apply(id);
        if (codec == null) {
            String msg = String.format(MISSING_COMPRESSION_MESSAGE, id);
            throw new CompressionException(msg);
        }
        return codec;
    }

    @Override
    public CompressionCodec resolveCompressionCodec(Header<?> header) {
        return locate(header);
    }
}

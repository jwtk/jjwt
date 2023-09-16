/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Assert;

//TODO: delete when deleting CompressionCodecResolver
public class CompressionCodecLocator implements Function<Header, CompressionAlgorithm>, Locator<CompressionAlgorithm> {

    private final CompressionCodecResolver resolver;

    public CompressionCodecLocator(CompressionCodecResolver resolver) {
        this.resolver = Assert.notNull(resolver, "CompressionCodecResolver cannot be null.");
    }

    @Override
    public CompressionAlgorithm apply(Header header) {
        return locate(header);
    }

    @Override
    public CompressionAlgorithm locate(Header header) {
        return resolver.resolveCompressionCodec(header);
    }
}

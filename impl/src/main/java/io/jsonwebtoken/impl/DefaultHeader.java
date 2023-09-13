/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.impl.lang.CompactMediaTypeIdConverter;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.Map;

public class DefaultHeader extends ParameterMap implements Header {

    static final Parameter<String> TYPE = Parameters.string(Header.TYPE, "Type");
    static final Parameter<String> CONTENT_TYPE = Parameters.builder(String.class)
            .setId(Header.CONTENT_TYPE).setName("Content Type")
            .setConverter(CompactMediaTypeIdConverter.INSTANCE).build();
    static final Parameter<String> ALGORITHM = Parameters.string(Header.ALGORITHM, "Algorithm");
    static final Parameter<String> COMPRESSION_ALGORITHM =
            Parameters.string(Header.COMPRESSION_ALGORITHM, "Compression Algorithm");
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated // TODO: remove for 1.0.0:
    static final Parameter<String> DEPRECATED_COMPRESSION_ALGORITHM =
            Parameters.string(Header.DEPRECATED_COMPRESSION_ALGORITHM, "Deprecated Compression Algorithm");

    static final Registry<String, Parameter<?>> PARAMS =
            Parameters.registry(TYPE, CONTENT_TYPE, ALGORITHM, COMPRESSION_ALGORITHM, DEPRECATED_COMPRESSION_ALGORITHM);

    public DefaultHeader(Map<String, ?> values) {
        super(PARAMS, values);
    }

    protected DefaultHeader(Registry<String, Parameter<?>> registry, Map<String, ?> values) {
        super(registry, values);
    }

    @Override
    public String getName() {
        return "JWT header";
    }

    @Override
    public String getType() {
        return get(TYPE);
    }

    @Override
    public String getContentType() {
        return get(CONTENT_TYPE);
    }

    @Override
    public String getAlgorithm() {
        return get(ALGORITHM);
    }

    @Override
    public String getCompressionAlgorithm() {
        String s = get(COMPRESSION_ALGORITHM);
        if (!Strings.hasText(s)) {
            s = get(DEPRECATED_COMPRESSION_ALGORITHM);
        }
        return s;
    }
}

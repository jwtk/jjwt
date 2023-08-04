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
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.Map;

public class DefaultHeader extends FieldMap implements Header {

    static final Field<String> TYPE = Fields.string(Header.TYPE, "Type");
    static final Field<String> CONTENT_TYPE = Fields.string(Header.CONTENT_TYPE, "Content Type");
    static final Field<String> ALGORITHM = Fields.string(Header.ALGORITHM, "Algorithm");
    static final Field<String> COMPRESSION_ALGORITHM = Fields.string(Header.COMPRESSION_ALGORITHM, "Compression Algorithm");
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated // TODO: remove for 1.0.0:
    static final Field<String> DEPRECATED_COMPRESSION_ALGORITHM = Fields.string(Header.DEPRECATED_COMPRESSION_ALGORITHM, "Deprecated Compression Algorithm");

    static final Registry<String, Field<?>> FIELDS = Fields.registry(TYPE, CONTENT_TYPE, ALGORITHM, COMPRESSION_ALGORITHM, DEPRECATED_COMPRESSION_ALGORITHM);

    public DefaultHeader(Map<String, ?> values) {
        super(FIELDS, values);
    }

    protected DefaultHeader(Registry<String, Field<?>> fields, Map<String, ?> values) {
        super(fields, values);
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

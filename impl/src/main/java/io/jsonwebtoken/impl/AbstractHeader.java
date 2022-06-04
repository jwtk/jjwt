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
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.util.Map;
import java.util.Set;

public abstract class AbstractHeader<T extends Header<T>> extends JwtMap implements Header<T> {

    static final Field<String> TYPE = Fields.string(Header.TYPE, "Type");
    static final Field<String> CONTENT_TYPE = Fields.string(Header.CONTENT_TYPE, "Content Type");
    static final Field<String> ALGORITHM = Fields.string(Header.ALGORITHM, "Algorithm");
    static final Field<String> COMPRESSION_ALGORITHM = Fields.string(Header.COMPRESSION_ALGORITHM, "Compression Algorithm");
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated // TODO: remove for 1.0.0:
    static final Field<String> DEPRECATED_COMPRESSION_ALGORITHM = Fields.string(Header.DEPRECATED_COMPRESSION_ALGORITHM, "Deprecated Compression Algorithm");

    static final Set<Field<?>> FIELDS = Collections.<Field<?>>setOf(TYPE, CONTENT_TYPE, ALGORITHM, COMPRESSION_ALGORITHM, DEPRECATED_COMPRESSION_ALGORITHM);

    protected AbstractHeader(Set<Field<?>> fieldSet) {
        super(fieldSet);
    }

    protected AbstractHeader(Set<Field<?>> fieldSet, Map<String, ?> values) {
        super(fieldSet, values);
    }

    @Override
    public String getName() {
        return "JWT header";
    }

    @SuppressWarnings("unchecked")
    protected T tthis() {
        return (T) this;
    }

    @Override
    public String getType() {
        return idiomaticGet(TYPE);
    }

    @Override
    public T setType(String typ) {
        put(TYPE, typ);
        return tthis();
    }

    @Override
    public String getContentType() {
        return idiomaticGet(CONTENT_TYPE);
    }

    @Override
    public T setContentType(String cty) {
        put(CONTENT_TYPE, cty);
        return tthis();
    }

    @Override
    public String getAlgorithm() {
        return idiomaticGet(ALGORITHM);
    }

    @Override
    public T setAlgorithm(String alg) {
        put(ALGORITHM, alg);
        return tthis();
    }

    @Override
    public String getCompressionAlgorithm() {
        String s = idiomaticGet(COMPRESSION_ALGORITHM);
        if (!Strings.hasText(s)) {
            s = idiomaticGet(DEPRECATED_COMPRESSION_ALGORITHM);
        }
        return s;
    }

    @Override
    public T setCompressionAlgorithm(String compressionAlgorithm) {
        put(COMPRESSION_ALGORITHM, compressionAlgorithm);
        return tthis();
    }
}

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
import io.jsonwebtoken.lang.Strings;

import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultHeader<T extends Header<T>> extends JwtMap implements Header<T> {

    public DefaultHeader() {
        super();
    }

    public DefaultHeader(Map<String, Object> map) {
        super(map);
    }

    @Override
    public String getType() {
        return getString(TYPE);
    }

    @Override
    public T setType(String typ) {
        setValue(TYPE, typ);
        return (T)this;
    }

    @Override
    public String getContentType() {
        return getString(CONTENT_TYPE);
    }

    @Override
    public T setContentType(String cty) {
        setValue(CONTENT_TYPE, cty);
        return (T)this;
    }

    @SuppressWarnings("deprecation")
    @Override
    public String getCompressionAlgorithm() {
        String alg = getString(COMPRESSION_ALGORITHM);
        if (!Strings.hasText(alg)) {
            alg = getString(DEPRECATED_COMPRESSION_ALGORITHM);
        }
        return alg;
    }

    @Override
    public T setCompressionAlgorithm(String compressionAlgorithm) {
        setValue(COMPRESSION_ALGORITHM, compressionAlgorithm);
        return (T) this;
    }

}

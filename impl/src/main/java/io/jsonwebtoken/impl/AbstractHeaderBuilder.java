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

import io.jsonwebtoken.Header;

import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractHeaderBuilder<H extends Header<H>, T extends HeaderBuilder<H, T>>
        implements HeaderBuilder<H, T> {

    protected final H header;

    protected AbstractHeaderBuilder() {
        this.header = newHeader();
        onNewHeader(this.header);
    }

    protected abstract H newHeader();

    protected void onNewHeader(H header) {
    }

    @SuppressWarnings("unchecked")
    protected final T tthis() {
        return (T) this;
    }

    @Override
    public T setType(String typ) {
        this.header.setType(typ);
        return tthis();
    }

    @Override
    public T setContentType(String cty) {
        this.header.setContentType(cty);
        return tthis();
    }

    @Override
    public T setAlgorithm(String alg) {
        this.header.setAlgorithm(alg);
        return tthis();
    }

    @Override
    public T setCompressionAlgorithm(String zip) {
        this.header.setCompressionAlgorithm(zip);
        return tthis();
    }

    @Override
    public H build() {
        return this.header;
    }

    @Override
    public T put(String key, Object value) {
        this.header.put(key, value);
        return tthis();
    }

    @Override
    public T remove(String key) {
        this.header.remove(key);
        return tthis();
    }

    @Override
    public T putAll(Map<? extends String, ?> m) {
        this.header.putAll(m);
        return tthis();
    }

    @Override
    public T clear() {
        this.header.clear();
        return tthis();
    }
}

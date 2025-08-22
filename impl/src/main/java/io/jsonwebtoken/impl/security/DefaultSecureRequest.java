/*
 * Copyright (C) 2022 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultSecureRequest<T, K extends Key> extends DefaultRequest<T> implements SecureRequest<T, K> {

    private final K KEY;

    public DefaultSecureRequest(T payload, Provider provider, SecureRandom secureRandom, K key) {
        super(payload, provider, secureRandom);
        this.KEY = Assert.notNull(key, "key cannot be null.");
    }

    @Override
    public K getKey() {
        return this.KEY;
    }

    static abstract class AbstractSecureRequestParams<T, K extends Key, M extends SecureRequest.Params<T, K, M>>
            extends AbstractRequestParams<T, M> implements SecureRequest.Params<T, K, M> {

        protected K key;

        @Override
        public M key(K key) {
            this.key = key;
            return self();
        }
    }

    @SuppressWarnings("unused") // instantiated via reflection in io.jsonwebtoken.security.Suppliers
    public static class Builder<T, K extends Key> extends AbstractSecureRequestParams<T, K, SecureRequest.Builder<T, K>>
            implements SecureRequest.Builder<T, K> {

        @Override
        public SecureRequest<T, K> build() {
            return new DefaultSecureRequest<>(this.payload, this.provider, this.random, this.key);
        }

        public static class Supplier<T, K extends Key> implements java.util.function.Supplier<SecureRequest.Builder<T, K>> {
            @Override
            public Builder<T, K> get() {
                return new Builder<>();
            }
        }
    }
}

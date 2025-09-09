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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Request;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultRequest<T> extends DefaultMessage<T> implements Request<T> {

    private final Provider provider;
    private final SecureRandom secureRandom;

    DefaultRequest(T payload, Provider provider, SecureRandom secureRandom) {
        super(payload);
        this.provider = provider;
        this.secureRandom = secureRandom;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }

    static abstract class AbstractRequestParams<T, M extends Params<T, M>>
            implements Params<T, M> {

        protected Provider provider;
        protected SecureRandom random;
        protected T payload;

        @SuppressWarnings("unchecked")
        protected final M self() {
            return (M) this;
        }

        @Override
        public M payload(T payload) {
            this.payload = payload;
            return self();
        }

        @Override
        public M provider(Provider provider) {
            this.provider = provider;
            return self();
        }

        @Override
        public M random(SecureRandom random) {
            this.random = random;
            return self();
        }
    }

    @SuppressWarnings("unused") // instantiated via reflection in io.jsonwebtoken.security.Suppliers
    public static class Builder<T> extends AbstractRequestParams<T, Request.Builder<T>> implements Request.Builder<T> {

        @Override
        public Request<T> build() {
            return new DefaultRequest<>(this.payload, this.provider, this.random);
        }

        public static class Supplier<T> implements java.util.function.Supplier<Builder<T>> {
            @Override
            public Builder<T> get() {
                return new Builder<>();
            }
        }
    }
}

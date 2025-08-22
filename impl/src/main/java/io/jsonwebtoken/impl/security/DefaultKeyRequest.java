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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<T> extends DefaultRequest<T> implements KeyRequest<T> {

    private final JweHeader header;
    private final AeadAlgorithm encryptionAlgorithm;

    public DefaultKeyRequest(T payload, Provider provider, SecureRandom secureRandom, JweHeader header, AeadAlgorithm encryptionAlgorithm) {
        super(payload, provider, secureRandom);
        this.header = Assert.notNull(header, "JweHeader/Builder cannot be null.");
        this.encryptionAlgorithm = Assert.notNull(encryptionAlgorithm, "AeadAlgorithm argument cannot be null.");
    }

    @Override
    public JweHeader getHeader() {
        return this.header;
    }

    @Override
    public AeadAlgorithm getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    static abstract class AbstractKeyRequestParams<T, M extends KeyRequest.Params<T, M>>
            extends AbstractRequestParams<T, M> implements KeyRequest.Params<T, M> {

        protected AeadAlgorithm aeadAlg;
        protected JweHeader header;

        @Override
        public M encryptionAlgorithm(AeadAlgorithm aeadAlg) {
            this.aeadAlg = aeadAlg;
            return self();
        }

        @Override
        public M header(JweHeader header) {
            this.header = header;
            return self();
        }
    }

    public static class Builder<K extends Key> extends AbstractKeyRequestParams<K, KeyRequest.Builder<K>>
            implements KeyRequest.Builder<K> {

        @Override
        public KeyRequest<K> build() {
            return new DefaultKeyRequest<>(this.payload, this.provider, this.random, this.header, this.aeadAlg);
        }

        public static class Supplier<K extends Key> implements java.util.function.Supplier<KeyRequest.Builder<K>> {
            @Override
            public KeyRequest.Builder<K> get() {
                return new Builder<>();
            }
        }
    }
}

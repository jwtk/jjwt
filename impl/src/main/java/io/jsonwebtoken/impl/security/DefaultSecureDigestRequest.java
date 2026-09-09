/*
 * Copyright © 2026 jsonwebtoken.io
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

import io.jsonwebtoken.security.SecureDigestRequest;

import java.io.InputStream;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

@SuppressWarnings("unused")
public class DefaultSecureDigestRequest<K extends Key> extends DefaultSecureRequest<InputStream, K> implements SecureDigestRequest<K> {

    public DefaultSecureDigestRequest(InputStream payload, Provider provider, SecureRandom secureRandom, K key) {
        super(payload, provider, secureRandom, key);
    }

    @SuppressWarnings("unused") // instantiated via reflection in io.jsonwebtoken.security.Suppliers
    public static class Builder<K extends Key> extends AbstractKeyedPayloadParams<InputStream, K, SecureDigestRequest.Builder<K>>
            implements SecureDigestRequest.Builder<K> {

        @Override
        public SecureDigestRequest<K> build() {
            return new DefaultSecureDigestRequest<>(this.payload, this.provider, this.random, this.key);
        }

        public static class Supplier<K extends Key> implements java.util.function.Supplier<SecureDigestRequest.Builder<K>> {
            @Override
            public SecureDigestRequest.Builder<K> get() {
                return new DefaultSecureDigestRequest.Builder<>();
            }
        }
    }
}

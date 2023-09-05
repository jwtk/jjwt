/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.security.KeySupplier;

import java.security.Key;
import java.security.Provider;

public class ProviderKey<T extends Key> implements Key, KeySupplier<T> {

    private final T key;

    private final Provider provider;

    public static Provider getProvider(Key key, Provider backup) {
        if (key instanceof ProviderKey<?>) {
            ProviderKey<?> pkey = (ProviderKey<?>) key;
            return Assert.stateNotNull(pkey.getProvider(), "ProviderKey provider can never be null.");
        }
        return backup;
    }

    @SuppressWarnings("unchecked")
    public static <K extends Key> K getKey(K key) {
        return key instanceof ProviderKey ? ((ProviderKey<K>) key).getKey() : key;
    }

    ProviderKey(Provider provider, T key) {
        this.provider = Assert.notNull(provider, "Provider cannot be null.");
        this.key = Assert.notNull(key, "Key argument cannot be null.");
        if (key instanceof ProviderKey<?>) {
            String msg = "Nesting not permitted.";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    public T getKey() {
        return this.key;
    }

    @Override
    public String getAlgorithm() {
        return this.key.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return this.key.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return this.key.getEncoded();
    }

    public final Provider getProvider() {
        return this.provider;
    }

}

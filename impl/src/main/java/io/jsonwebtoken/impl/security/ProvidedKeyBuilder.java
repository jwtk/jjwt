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
import io.jsonwebtoken.security.KeyBuilder;

import java.security.Key;

abstract class ProvidedKeyBuilder<K extends Key, B extends KeyBuilder<K, B>> extends AbstractSecurityBuilder<K, B>
        implements KeyBuilder<K, B> {

    protected final K key;

    ProvidedKeyBuilder(K key) {
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    @Override
    public final K build() {
        if (this.key instanceof ProviderKey) { // already wrapped, don't wrap again:
            return this.key;
        }
        return doBuild();
    }

    abstract K doBuild();
}

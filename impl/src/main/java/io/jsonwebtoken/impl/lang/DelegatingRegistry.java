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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;

/**
 * {@code Registry} implementation that delegates all calls to an internal Registry instance.
 *
 * @param <K> Registry key type
 * @param <V> Registry value type
 * @since JJWT_RELEASE_VERSION
 */
public class DelegatingRegistry<K, V> extends DelegatingMap<K, V, Registry<K, V>> implements Registry<K, V> {

    protected DelegatingRegistry(Registry<K, V> registry) {
        super(registry);
        this.DELEGATE = Assert.notEmpty(registry, "Delegate registry cannot be null or empty.");
    }

    @Override
    public V forKey(K key) throws IllegalArgumentException {
        return DELEGATE.forKey(key);
    }
}

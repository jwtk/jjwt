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

import io.jsonwebtoken.lang.MapMutator;

import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DelegatingMapMutator<K, V, D extends Map<K, V>, T extends MapMutator<K, V, T>>
        extends DelegatingMap<K, V, D> implements MapMutator<K, V, T> {

    protected DelegatingMapMutator(D delegate) {
        super(delegate);
    }

    @SuppressWarnings("unchecked")
    protected final T self() {
        return (T) this;
    }

    @Override
    public T empty() {
        clear();
        return self();
    }

    @Override
    public T add(K key, V value) {
        put(key, value);
        return self();
    }

    @Override
    public T add(Map<? extends K, ? extends V> m) {
        putAll(m);
        return self();
    }

    @Override
    public T delete(K key) {
        remove(key);
        return self();
    }
}

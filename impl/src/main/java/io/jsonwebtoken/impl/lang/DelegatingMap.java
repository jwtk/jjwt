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

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * A {@code Map} implementation that delegates all calls to an internal Map instance.
 *
 * @param <K> Map key type
 * @param <V> Map value type
 * @since JJWT_RELEASE_VERSION
 */
public class DelegatingMap<K, V, T extends Map<K, V>> implements Map<K, V> {

    protected T DELEGATE;

    /**
     * Initializes the instance with specified non-null backing delegate Map.
     *
     * @param delegate non-null delegate map to use for all map method implementations
     * @throws IllegalArgumentException if {@code delegate} is null.
     */
    protected DelegatingMap(T delegate) {
        setDelegate(delegate);
    }

    protected void setDelegate(T delegate) {
        this.DELEGATE = Assert.notNull(delegate, "Delegate cannot be null.");
    }

    @Override
    public int size() {
        return DELEGATE.size();
    }

    @Override
    public Collection<V> values() {
        return DELEGATE.values();
    }

    @Override
    public V get(Object id) {
        return DELEGATE.get(id);
    }

    @Override
    public boolean isEmpty() {
        return DELEGATE.isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        return DELEGATE.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return DELEGATE.containsValue(value);
    }

    @Override
    public V put(K key, V value) {
        return DELEGATE.put(key, value);
    }

    @Override
    public V remove(Object key) {
        return DELEGATE.remove(key);
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> m) {
        DELEGATE.putAll(m);
    }

    @Override
    public void clear() {
        DELEGATE.clear();
    }

    @Override
    public Set<K> keySet() {
        return DELEGATE.keySet();
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
        return DELEGATE.entrySet();
    }
}

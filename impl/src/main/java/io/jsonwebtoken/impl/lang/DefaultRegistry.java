/*
 * Copyright © 2022 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultRegistry<K, V> extends DelegatingMap<K, V, Map<K, V>> implements Registry<K, V>, Function<K, V> {

    private final String qualifiedKeyName;

    private static <K, V> Map<K, V> toMap(Collection<? extends V> values, Function<V, K> keyFn) {
        Assert.notEmpty(values, "Collection of values may not be null or empty.");
        Assert.notNull(keyFn, "Key function cannot be null.");
        Map<K, V> m = new LinkedHashMap<>(values.size());
        for (V value : values) {
            K key = Assert.notNull(keyFn.apply(value), "Key function cannot return a null value.");
            m.put(key, value);
        }
        return Collections.immutable(m);
    }

    public DefaultRegistry(String name, String keyName, Collection<? extends V> values, Function<V, K> keyFn) {
        super(toMap(values, keyFn));
        name = Assert.hasText(Strings.clean(name), "name cannot be null or empty.");
        keyName = Assert.hasText(Strings.clean(keyName), "keyName cannot be null or empty.");
        this.qualifiedKeyName = name + " " + keyName;
    }

    @Override
    public V apply(K k) {
        return get(k);
    }

    @Override
    public V forKey(K key) {
        V value = get(key);
        if (value == null) {
            String msg = "Unrecognized " + this.qualifiedKeyName + ": " + key;
            throw new IllegalArgumentException(msg);
        }
        return value;
    }

    static <T> T immutable() {
        throw new UnsupportedOperationException("Registries are immutable and cannot be modified.");
    }

    @Override
    public V put(K key, V value) {
        return immutable();
    }

    @Override
    public V remove(Object key) {
        return immutable();
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> m) {
        immutable();
    }

    @Override
    public void clear() {
        immutable();
    }
}

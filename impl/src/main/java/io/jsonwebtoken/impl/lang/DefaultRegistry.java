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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultRegistry<K, V> implements Registry<K, V> {

    private final Map<K, V> VALUES;

    public DefaultRegistry(Collection<V> values, Function<V, K> keyFn) {
        Assert.notEmpty(values, "Collection of values may not be null or empty.");
        Assert.notNull(keyFn, "Key function cannot be null.");
        Map<K, V> m = new LinkedHashMap<>(values.size());
        for (V value : values) {
            K key = Assert.notNull(keyFn.apply(value), "Key function cannot return a null value.");
            m.put(key, value);
        }
        this.VALUES = Collections.immutable(m);
    }

    @Override
    public V apply(K k) {
        Assert.notNull(k, "Lookup value cannot be null.");
        return VALUES.get(k);
    }

    @Override
    public Collection<V> values() {
        return VALUES.values();
    }

}

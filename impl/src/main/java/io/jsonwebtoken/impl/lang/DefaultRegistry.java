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

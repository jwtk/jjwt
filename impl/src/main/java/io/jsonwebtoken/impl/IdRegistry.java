package io.jsonwebtoken.impl;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class IdRegistry<T extends Identifiable> implements Registry<String, T> {

    private final Map<String, T> INSTANCES;

    public IdRegistry(Collection<T> instances) {
        Assert.notEmpty(instances, "Collection of Identifiable instances may not be null or empty.");
        Map<String, T> m = new LinkedHashMap<>(instances.size());
        for (T instance : instances) {
            String id = Assert.hasText(Strings.clean(instance.getId()), "All Identifiable instances within the collection cannot have a null or empty id.");
            m.put(id, instance);
        }
        this.INSTANCES = java.util.Collections.unmodifiableMap(m);
    }

    @Override
    public T apply(String id) {
        Assert.hasText(id, "id argument cannot be null or empty.");
        //try constant time lookup first.  This will satisfy 99% of invocations:
        T instance = INSTANCES.get(id);
        if (instance != null) {
            return instance;
        }
        //fall back to case-insensitive lookup:
        for (T i : INSTANCES.values()) {
            if (id.equalsIgnoreCase(i.getId())) {
                return i;
            }
        }
        return null; //no match
    }

    @Override
    public Collection<T> values() {
        return this.INSTANCES.values();
    }
}

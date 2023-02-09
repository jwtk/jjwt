package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;

import java.util.Collection;

abstract class DelegatingRegistry<T> implements Registry<String, T> {

    private final Registry<String, T> REGISTRY;

    protected DelegatingRegistry(Registry<String, T> registry) {
        this.REGISTRY = Assert.notNull(registry, "Registry cannot be null.");
        Assert.notEmpty(this.REGISTRY.values(), "Registry cannot be empty.");
    }

    @Override
    public Collection<T> values() {
        return REGISTRY.values();
    }

    @Override
    public T get(String id) throws IllegalArgumentException {
        return REGISTRY.get(id);
    }

    @Override
    public T find(String id) {
        return REGISTRY.find(id);
    }
}

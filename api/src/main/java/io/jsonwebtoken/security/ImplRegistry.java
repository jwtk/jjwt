package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.DelegatingRegistry;
import io.jsonwebtoken.lang.Registry;

/**
 * A Registry that looks up its required delegate instance by class name.
 *
 * @param <V> Registry value typ.
 */
// Package protected on purpose, we don't want this exposed to be used by API users:
class ImplRegistry<V> extends DelegatingRegistry<String, V> {

    protected ImplRegistry(String implClassName) {
        super(Classes.<Registry<String, V>>newInstance(implClassName));
    }

    // do not change this visibility.  Raw type method signature not be publicly exposed
    @SuppressWarnings("unchecked")
    <T> T doForKey(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return (T) forKey(id);
    }
}

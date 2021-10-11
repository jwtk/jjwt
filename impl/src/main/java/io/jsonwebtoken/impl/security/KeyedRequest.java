package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeySupplier;
import io.jsonwebtoken.security.SecurityRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class KeyedRequest<K extends Key> extends DefaultSecurityRequest implements SecurityRequest, KeySupplier<K> {

    private final K key;

    public KeyedRequest(Provider provider, SecureRandom secureRandom, K key) {
        super(provider, secureRandom);
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    @Override
    public K getKey() {
        return this.key;
    }
}

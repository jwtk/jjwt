package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultSecureRequest<T, K extends Key> extends DefaultRequest<T> implements SecureRequest<T, K> {

    private final K KEY;

    public DefaultSecureRequest(T payload, Provider provider, SecureRandom secureRandom, K key) {
        super(payload, provider, secureRandom);
        this.KEY = Assert.notNull(key, "key cannot be null.");
    }

    @Override
    public K getKey() {
        return this.KEY;
    }
}

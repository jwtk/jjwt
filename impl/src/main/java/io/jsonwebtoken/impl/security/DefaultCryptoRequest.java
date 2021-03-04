package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultCryptoRequest<T, K extends Key> extends DefaultPayloadSupplier<T> implements CryptoRequest<T, K>{

    private final Provider provider;
    private final SecureRandom secureRandom;
    private final K key;

    public DefaultCryptoRequest(Provider provider, SecureRandom secureRandom, T data, K key) {
        super(data);
        this.provider = provider;
        this.secureRandom = secureRandom;
        this.key = Assert.notNull(key, "key cannot be null.");
    }

    @Override
    public K getKey() {
        return this.key;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }
}

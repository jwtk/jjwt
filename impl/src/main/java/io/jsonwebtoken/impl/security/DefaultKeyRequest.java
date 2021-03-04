package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<T, K extends Key> extends DefaultCryptoRequest<T, K> implements KeyRequest<T, K> {

    private final JweHeader header;

    public DefaultKeyRequest(Provider provider, SecureRandom secureRandom, T data, K key, JweHeader header) {
        super(provider, secureRandom, data, key);
        this.header = Assert.notNull(header, "JweHeader cannot be null.");
    }

    @Override
    public JweHeader getHeader() {
        return this.header;
    }
}

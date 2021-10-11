package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<T, K extends Key> extends DefaultCryptoRequest<T, K> implements KeyRequest<T, K> {

    private final JweHeader header;
    private final SymmetricAeadAlgorithm encryptionAlgorithm;

    public DefaultKeyRequest(Provider provider, SecureRandom secureRandom, T payload, K key, JweHeader header, SymmetricAeadAlgorithm encryptionAlgorithm) {
        super(provider, secureRandom, payload, key);
        this.header = Assert.notNull(header, "JweHeader cannot be null.");
        this.encryptionAlgorithm = Assert.notNull(encryptionAlgorithm, "SymmetricAeadAlgorithm argument cannot be null.");
    }

    @Override
    protected T assertValidPayload(T payload) throws IllegalArgumentException {
        if (payload != null) {
            return super.assertValidPayload(payload);
        }
        return null;
    }

    @Override
    public JweHeader getHeader() {
        return this.header;
    }

    @Override
    public SymmetricAeadAlgorithm getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }
}

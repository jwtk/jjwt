package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<K extends Key> extends DefaultKeyedRequest<K> implements KeyRequest<K> {

    private final JweHeader header;
    private final AeadAlgorithm encryptionAlgorithm;

    public DefaultKeyRequest(Provider provider, SecureRandom secureRandom, K key, JweHeader header, AeadAlgorithm encryptionAlgorithm) {
        super(provider, secureRandom, key);
        this.header = Assert.notNull(header, "JweHeader cannot be null.");
        this.encryptionAlgorithm = Assert.notNull(encryptionAlgorithm, "AeadAlgorithm argument cannot be null.");
    }

    @Override
    public JweHeader getHeader() {
        return this.header;
    }

    @Override
    public AeadAlgorithm getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }
}

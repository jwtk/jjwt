package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<T> extends DefaultRequest<T> implements KeyRequest<T> {

    private final JweHeader header;
    private final AeadAlgorithm encryptionAlgorithm;

    public DefaultKeyRequest(T payload, Provider provider, SecureRandom secureRandom, JweHeader header, AeadAlgorithm encryptionAlgorithm) {
        super(payload, provider, secureRandom);
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

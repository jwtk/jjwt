package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptionKeyRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultDecryptionKeyRequest<K extends Key> extends DefaultKeyRequest<byte[]> implements DecryptionKeyRequest<K> {

    private final K decryptionKey;

    public DefaultDecryptionKeyRequest(byte[] encryptedCek, Provider provider, SecureRandom secureRandom, JweHeader header, AeadAlgorithm encryptionAlgorithm, K decryptionKey) {
        super(encryptedCek, provider, secureRandom, header, encryptionAlgorithm);
        this.decryptionKey = Assert.notNull(decryptionKey, "decryption key cannot be null.");
    }

    @Override
    protected void assertBytePayload(byte[] payload) {
        Assert.notNull(payload, "encrypted key bytes cannot be null (but may be empty.");
    }

    @Override
    public K getKey() {
        return this.decryptionKey;
    }
}

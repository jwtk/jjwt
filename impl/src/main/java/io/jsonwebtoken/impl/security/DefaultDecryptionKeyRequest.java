package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultDecryptionKeyRequest<K extends Key> extends DefaultKeyRequest<K> implements DecryptionKeyRequest<K> {

    private final byte[] payload;

    public DefaultDecryptionKeyRequest(Provider provider, SecureRandom secureRandom, K key, JweHeader header, SymmetricAeadAlgorithm encryptionAlgorithm, byte[] payload) {
        super(provider, secureRandom, key, header, encryptionAlgorithm);
        this.payload = payload;
    }

    @Override
    public byte[] getPayload() {
        return this.payload;
    }
}

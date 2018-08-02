package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AeadRequest;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAesEncryptionRequest<T> extends DefaultCryptoRequest<T, SecretKey> implements AeadRequest<T, SecretKey> {

    private final byte[] aad;

    public DefaultAesEncryptionRequest(T data, SecretKey key, Provider provider, SecureRandom secureRandom, byte[] aad) {
        super(data, key, provider, secureRandom);
        this.aad = aad;
    }

    public DefaultAesEncryptionRequest(T data, SecretKey key, byte[] aad) {
        this(data, key, null, null, aad);
    }

    @Override
    public byte[] getAssociatedData() {
        return this.aad;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.InitializationVectorSupplier;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAeadRequest extends DefaultCryptoRequest<SecretKey> implements AeadRequest, InitializationVectorSupplier {

    private final byte[] IV;

    private final byte[] AAD;

    DefaultAeadRequest(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad, byte[] iv) {
        super(provider, secureRandom, data, key);
        this.AAD = aad;
        this.IV = iv;
    }

    public DefaultAeadRequest(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad) {
        this(provider, secureRandom, data, key, aad, null);
    }

    public DefaultAeadRequest(byte[] data, SecretKey key, byte[] aad) {
        this(null, null, data, key, aad, null);
    }

    @Override
    public byte[] getAssociatedData() {
        return this.AAD;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.IV;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.InitializationVectorSupplier;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAeadRequest extends DefaultSecureRequest<byte[], SecretKey>
        implements AeadRequest, InitializationVectorSupplier {

    private final byte[] IV;

    private final byte[] AAD;

    DefaultAeadRequest(byte[] data, Provider provider, SecureRandom secureRandom, SecretKey key, byte[] aad, byte[] iv) {
        super(data, provider, secureRandom, key);
        this.AAD = aad;
        this.IV = iv;
    }

    public DefaultAeadRequest(byte[] data, Provider provider, SecureRandom secureRandom, SecretKey key, byte[] aad) {
        this(data, provider, secureRandom, key, aad, null);
    }

    public DefaultAeadRequest(byte[] data, SecretKey key, byte[] aad) {
        this(data, null, null, key, aad, null);
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

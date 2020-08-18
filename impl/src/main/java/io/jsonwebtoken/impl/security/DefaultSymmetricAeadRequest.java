package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.InitializationVectorSource;
import io.jsonwebtoken.security.SymmetricAeadRequest;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultSymmetricAeadRequest extends DefaultCryptoRequest<byte[], SecretKey> implements SymmetricAeadRequest, InitializationVectorSource {

    private final byte[] IV;

    private final byte[] AAD;

    DefaultSymmetricAeadRequest(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad, byte[] iv) {
        super(provider, secureRandom, data, key);
        this.AAD = aad;
        this.IV = iv;
    }

    public DefaultSymmetricAeadRequest(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad) {
        this(provider, secureRandom, data, key, aad, null);
    }

    public DefaultSymmetricAeadRequest(byte[] data, SecretKey key, byte[] aad) {
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

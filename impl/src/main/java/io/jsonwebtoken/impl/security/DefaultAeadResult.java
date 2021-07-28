package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest;
import io.jsonwebtoken.security.AeadResult;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAeadResult extends DefaultSymmetricAeadRequest implements AeadResult, SymmetricAeadDecryptionRequest {

    private final byte[] TAG;

    public DefaultAeadResult(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad, byte[] tag, byte[] iv) {
        super(provider, secureRandom, data, key, aad, iv);
        Assert.notEmpty(iv, "initialization vector cannot be null or empty.");
        this.TAG = Assert.notEmpty(tag, "authentication tag cannot be null or empty.");
    }

    @Override
    public byte[] getAuthenticationTag() {
        return this.TAG;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.DecryptAeadRequest;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAeadResult extends DefaultAeadRequest implements AeadResult, DecryptAeadRequest {

    private final byte[] TAG;

    public DefaultAeadResult(Provider provider, SecureRandom secureRandom, byte[] data, SecretKey key, byte[] aad, byte[] tag, byte[] iv) {
        super(data, provider, secureRandom, key, aad, iv);
        Assert.notEmpty(iv, "initialization vector cannot be null or empty.");
        this.TAG = Assert.notEmpty(tag, "authentication tag cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.TAG;
    }
}

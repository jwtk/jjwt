package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultVerifySecureDigestRequest<K extends Key> extends DefaultSecureRequest<byte[], K> implements VerifySecureDigestRequest<K> {

    private final byte[] digest;

    public DefaultVerifySecureDigestRequest(byte[] payload, Provider provider, SecureRandom secureRandom, K key, byte[] digest) {
        super(payload, provider, secureRandom, key);
        this.digest = Assert.notEmpty(digest, "Digest byte array cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.digest;
    }
}

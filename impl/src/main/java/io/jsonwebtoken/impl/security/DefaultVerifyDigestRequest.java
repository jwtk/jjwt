package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.VerifyDigestRequest;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultVerifyDigestRequest extends DefaultRequest<byte[]> implements VerifyDigestRequest {

    private final byte[] digest;

    public DefaultVerifyDigestRequest(byte[] payload, Provider provider, SecureRandom secureRandom, byte[] digest) {
        super(payload, provider, secureRandom);
        this.digest = Assert.notEmpty(digest, "Digest byte array cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.digest;
    }
}

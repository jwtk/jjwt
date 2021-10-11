package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultVerifySignatureRequest<K extends Key> extends DefaultSignatureRequest<K> implements VerifySignatureRequest<K> {

    private final byte[] signature;

    public DefaultVerifySignatureRequest(Provider provider, SecureRandom secureRandom, byte[] data, K key, byte[] signature) {
        super(provider, secureRandom, data, key);
        this.signature = Assert.notEmpty(signature, "Signature byte array cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.signature;
    }
}

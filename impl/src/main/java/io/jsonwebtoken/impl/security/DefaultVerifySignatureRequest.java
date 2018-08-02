package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultVerifySignatureRequest extends DefaultCryptoRequest<byte[], Key> implements VerifySignatureRequest {

    private final byte[] signature;

    public DefaultVerifySignatureRequest(byte[] data, Key key, Provider provider, SecureRandom secureRandom, byte[] signature) {
        super(data, key, provider, secureRandom);
        this.signature = Assert.notEmpty(signature, "Signature byte array cannot be null or empty.");
    }

    @Override
    public byte[] getSignature() {
        return this.signature;
    }
}

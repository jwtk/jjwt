package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;

public class DefaultKeyResult implements KeyResult {

    private final byte[] payload;
    private final SecretKey key;

    public DefaultKeyResult(SecretKey key) {
        this(key, Bytes.EMPTY);
    }

    public DefaultKeyResult(SecretKey key, byte[] encryptedKey) {
        this.payload = Assert.notNull(encryptedKey, "encryptedKey cannot be null (but can be empty).");
        this.key = Assert.notNull(key, "Key argument cannot be null.");
    }

    @Override
    public byte[] getPayload() {
        return this.payload;
    }

    @Override
    public SecretKey getKey() {
        return this.key;
    }
}

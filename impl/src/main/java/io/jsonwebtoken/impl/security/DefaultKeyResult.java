package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;

public class DefaultKeyResult implements KeyResult {

    private final byte[] encryptedKey;
    private final SecretKey key;

    public DefaultKeyResult(SecretKey key) {
        this(key, Bytes.EMPTY);
    }

    public DefaultKeyResult(SecretKey key, byte[] encryptedKey) {
        this.encryptedKey = Assert.notNull(encryptedKey, "encryptedKey cannot be null (but can be empty).");
        this.key = Assert.notNull(key, "Key argument cannot be null.");
    }

    @Override
    public byte[] getContent() {
        return this.encryptedKey;
    }

    @Override
    public SecretKey getKey() {
        return this.key;
    }
}

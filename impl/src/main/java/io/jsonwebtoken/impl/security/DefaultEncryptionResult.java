package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptionResult;

class DefaultEncryptionResult implements EncryptionResult {

    protected final byte[] ciphertext;

    DefaultEncryptionResult(byte[] ciphertext) {
        this.ciphertext = Assert.notEmpty(ciphertext, "ciphertext cannot be null or empty.");
    }

    @Override
    public byte[] getCiphertext() {
        return this.ciphertext;
    }
}

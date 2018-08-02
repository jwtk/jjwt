package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DirectEncryptionMode implements KeyManagementMode {

    private final SecretKey key;

    DirectEncryptionMode(SecretKey key) {
        this.key = Assert.notNull(key, "SecretKey argument cannot be null.");
    }

    @Override
    public SecretKey getKey(GetKeyRequest ignored) {
        return this.key;
    }
}

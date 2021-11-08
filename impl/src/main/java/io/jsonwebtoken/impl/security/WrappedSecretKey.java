package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class WrappedSecretKey implements SecretKey {

    private final String algorithm;
    private final SecretKey key;

    public WrappedSecretKey(SecretKey key, String algorithm) {
        this.key = Assert.notNull(key, "SecretKey cannot be null.");
        this.algorithm = Assert.hasText(algorithm, "Algorithm cannot be null or empty.");
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getFormat() {
        return this.key.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return this.key.getEncoded();
    }
}

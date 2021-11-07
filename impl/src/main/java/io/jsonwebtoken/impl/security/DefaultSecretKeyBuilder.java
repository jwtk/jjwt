package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecretKeyBuilder;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultSecretKeyBuilder implements SecretKeyBuilder {

    protected final String JCA_NAME;
    protected final int BIT_LENGTH;
    protected Provider provider;
    protected SecureRandom random;

    public DefaultSecretKeyBuilder(String jcaName, int bitLength) {
        this.JCA_NAME = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        if (bitLength % Byte.SIZE != 0) {
            String msg = "bitLength must be a multiple of 8";
            throw new IllegalArgumentException(msg);
        }
        this.BIT_LENGTH = Assert.gt(bitLength, 0, "bitLength must be > 0");
        setRandom(Randoms.secureRandom());
    }

    @Override
    public SecretKeyBuilder setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public SecretKeyBuilder setRandom(SecureRandom random) {
        this.random = random != null ? random : Randoms.secureRandom();
        return this;
    }

    @Override
    public SecretKey build() {
        JcaTemplate template = new JcaTemplate(JCA_NAME, this.provider, this.random);
        return template.generateSecretKey(this.BIT_LENGTH);
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class DefaultKeyPairBuilder implements KeyPairBuilder {

    private final String jcaName;
    private final int bitLength;
    private final AlgorithmParameterSpec params;
    private Provider provider;
    private SecureRandom random;

    public DefaultKeyPairBuilder(String jcaName, int bitLength) {
        this.jcaName = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.bitLength = Assert.gt(bitLength, 0, "bitLength must be a positive integer greater than 0");
        this.params = null;
    }

    public DefaultKeyPairBuilder(String jcaName, AlgorithmParameterSpec params) {
        this.jcaName = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.params = Assert.notNull(params, "AlgorithmParameterSpec params cannot be null.");
        this.bitLength = 0;
    }

    @Override
    public KeyPair build() {
        JcaTemplate template = new JcaTemplate(this.jcaName, this.provider, this.random);
        if (this.params != null) {
            return template.generateKeyPair(this.params);
        } else {
            return template.generateKeyPair(this.bitLength);
        }
    }

    @Override
    public KeyPairBuilder setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public KeyPairBuilder setRandom(SecureRandom random) {
        this.random = random;
        return this;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPair;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class DefaultKeyPairBuilder<A extends PublicKey, B extends PrivateKey> implements KeyPairBuilder<A, B> {

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

    protected java.security.KeyPair generateJdkPair() throws io.jsonwebtoken.security.SecurityException {
        JcaTemplate template = new JcaTemplate(this.jcaName, this.provider, this.random);
        if (this.params != null) {
            return template.generateKeyPair(this.params);
        } else {
            return template.generateKeyPair(this.bitLength);
        }
    }

    @Override
    public KeyPair<A, B> build() {
        java.security.KeyPair pair = generateJdkPair();
        @SuppressWarnings("unchecked") A publicKey = (A) pair.getPublic();
        @SuppressWarnings("unchecked") B privateKey = (B) pair.getPrivate();
        return new DefaultKeyPair<>(publicKey, privateKey);
    }

    @Override
    public KeyPairBuilder<A, B> setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public KeyPairBuilder<A, B> setRandom(SecureRandom random) {
        this.random = random;
        return this;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PbeKey;
import io.jsonwebtoken.security.PbeKeyBuilder;

public class DefaultPbeKeyBuilder implements PbeKeyBuilder<PbeKey> {

    private char[] password;
    private int iterations;

    @Override
    public DefaultPbeKeyBuilder setPassword(final char[] password) {
        this.password = Assert.notEmpty(password, "password cannot be null or empty.");
        return this;
    }

    @Override
    public DefaultPbeKeyBuilder setIterations(final int iterations) {
        Assert.isTrue(iterations > 0, "iterations must be a positive integer.");
        this.iterations = iterations;
        return this;
    }

    @Override
    public PbeKey build() {
        return new DefaultPbeKey(this.password, this.iterations);
    }
}

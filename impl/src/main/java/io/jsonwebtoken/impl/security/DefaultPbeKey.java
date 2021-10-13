package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.PbeKey;

public class DefaultPbeKey implements PbeKey {

    private static final String RAW_FORMAT = "RAW";
    private static final String NONE_ALGORITHM = "NONE";

    private volatile boolean destroyed;
    private final char[] chars;
    private final int iterations;

    public DefaultPbeKey(char[] password, int iterations) {
        if (iterations <= 0) {
            String msg = "iterations must be a positive integer. Value: " + iterations;
            throw new IllegalArgumentException(msg);
        }
        this.iterations = iterations;
        this.chars = Assert.notEmpty(password, "Password character array cannot be null or empty.");
    }

    private void assertActive() {
        if (destroyed) {
            String msg = "PBKey has been destroyed. Password characters or bytes may not be obtained.";
            throw new IllegalStateException(msg);
        }
    }

    @Override
    public char[] getPassword() {
        assertActive();
        return this.chars.clone();
    }

    @Override
    public int getIterations() {
        return this.iterations;
    }

    @Override
    public String getAlgorithm() {
        return NONE_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return RAW_FORMAT;
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("getEncoded is not supported for PbeKey instances.");
    }

    @Override
    public void destroy() {
        if (!destroyed && chars != null) {
            java.util.Arrays.fill(chars, '\u0000');
        }
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(this.chars);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof DefaultPbeKey) {
            DefaultPbeKey other = (DefaultPbeKey) obj;
            return this.iterations == other.iterations &&
                Objects.nullSafeEquals(this.chars, other.chars);
        }
        return false;
    }

    @Override
    public String toString() {
        return "password=<redacted>, iterations=" + this.iterations;
    }
}

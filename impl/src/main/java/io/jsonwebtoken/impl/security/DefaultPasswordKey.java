package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.PasswordKey;

public class DefaultPasswordKey implements PasswordKey {

    private static final String RAW_FORMAT = "RAW";
    private static final String NONE_ALGORITHM = "NONE";
    private static final String DESTROYED_MSG = "PasswordKey has been destroyed. Password character array may not be obtained.";
    private static final String ENCODED_DISABLED_MSG =
        "getEncoded() is disabled for PasswordKeys as they are intended to be used " +
            "with key derivation algorithms only.  Passwords should never be used as direct inputs for " +
            "cryptographic operations such as authenticated hashing or encryption; if you see this " +
            "exception message, it is likely that the associated PasswordKey is being used incorrectly.";

    private volatile boolean destroyed;
    private final char[] password;

    public DefaultPasswordKey(char[] password) {
        this.password = Assert.notNull(password, "Password character array cannot be null or empty.");
    }

    private void assertActive() {
        if (destroyed) {
            throw new IllegalStateException(DESTROYED_MSG);
        }
    }

    @Override
    public char[] getPassword() {
        assertActive();
        return this.password.clone();
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
        throw new UnsupportedOperationException(ENCODED_DISABLED_MSG);
    }

    @Override
    public void destroy() {
        java.util.Arrays.fill(password, '\u0000');
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return this.destroyed;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(this.password);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof DefaultPasswordKey) {
            DefaultPasswordKey other = (DefaultPasswordKey) obj;
            return Objects.nullSafeEquals(this.password, other.password);
        }
        return false;
    }

    @Override
    public final String toString() {
        return "password=<redacted>";
    }
}

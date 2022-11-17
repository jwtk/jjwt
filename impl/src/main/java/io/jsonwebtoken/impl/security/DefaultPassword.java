package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.Password;

public class DefaultPassword implements Password {

    private static final String NONE_ALGORITHM = "NONE";
    private static final String DESTROYED_MSG = "Password has been destroyed. Password character array may not be obtained.";
    private static final String ENCODED_DISABLED_MSG =
        "getEncoded() is disabled for Password instances as they are intended to be used " +
            "with key derivation algorithms only.  Passwords should never be used as direct inputs for " +
            "cryptographic operations such as authenticated hashing or encryption; if you see this " +
            "exception message, it is likely that the associated Password instance is being used incorrectly.";

    private volatile boolean destroyed;
    private final char[] password;

    public DefaultPassword(char[] password) {
        this.password = Assert.notEmpty(password, "Password character array cannot be null or empty.");
    }

    private void assertActive() {
        if (destroyed) {
            throw new IllegalStateException(DESTROYED_MSG);
        }
    }

    @Override
    public char[] toCharArray() {
        assertActive();
        return this.password.clone();
    }

    @Override
    public String getAlgorithm() {
        return NONE_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return null; // encoding isn't supported, so we return null per the Key#getFormat() JavaDoc
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException(ENCODED_DISABLED_MSG);
    }

    public void destroy() {
        java.util.Arrays.fill(password, '\u0000');
        this.destroyed = true;
    }

    public boolean isDestroyed() {
        return this.destroyed;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(this.password);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof DefaultPassword) {
            DefaultPassword other = (DefaultPassword) obj;
            return this.destroyed == other.destroyed && Objects.nullSafeEquals(this.password, other.password);
        }
        return false;
    }

    @Override
    public final String toString() {
        return "<redacted>";
    }
}

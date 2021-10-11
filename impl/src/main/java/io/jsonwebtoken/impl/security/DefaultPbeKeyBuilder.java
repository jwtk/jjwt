package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PbeKey;
import io.jsonwebtoken.security.PbeKeyBuilder;

import javax.crypto.interfaces.PBEKey;
import javax.security.auth.Destroyable;

//
// MAINTAINER NOTE:
//
// If editing/modifying this class, DO NOT attempt to call jcaKey.getPassword(): doing so creates a clone of that
// character array.  There is no need to create copies of sensitive data (that we would be responsible for cleaning up)
// since the JcaPbeKey implementation will just delegate to the jcaKey as needed.
//
public class DefaultPbeKeyBuilder<K extends PbeKey> implements PbeKeyBuilder<K>, Destroyable {

    private char[] password;
    private int workFactor;
    private PBEKey jcaKey;
    private volatile boolean destroyed;

    private static char[] assertPassword(char[] password) {
        Assert.notEmpty(password, "Password cannot be null or empty.");
        return password;
    }

    private static int assertWorkFactor(int workFactor) {
        if (workFactor < 0) {
            String msg = "workFactor cannot be negative.";
            throw new IllegalArgumentException(msg);
        }
        return workFactor;
    }

    @Override
    public PbeKeyBuilder<K> forKey(PBEKey jcaKey) {
        this.jcaKey = Assert.notNull(jcaKey, "PBEKey cannot be null.");
        return this;
    }

    @Override
    public PbeKeyBuilder<K> setPassword(String password) {
        return setPassword(Assert.notNull(password, "password cannot be null.").toCharArray());
    }

    @Override
    public DefaultPbeKeyBuilder<K> setPassword(char[] password) {
        this.password = password;
        return this;
    }

    @Override
    public DefaultPbeKeyBuilder<K> setWorkFactor(int workFactor) {
        this.workFactor = workFactor;
        return this;
    }

    @Override
    public void destroy() {
        if (this.password != null) {
            destroyed = true;
            java.util.Arrays.fill(this.password, '\u0000');
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void assertActive() {
        if (destroyed) {
            String msg = "This PbeKeyBuilder has been destroyed in order to clean/zero-out internal password " +
                "arrays for safety.  Please use a new builder for each PbeKey instance you need to create.";
            throw new IllegalStateException(msg);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public K build() {
        try {
            if (this.jcaKey != null) {
                return (K) new JcaPbeKey(this.jcaKey);
            }
            assertActive();
            assertPassword(this.password);
            assertWorkFactor(this.workFactor);
            return (K) new DefaultPbeKey(this.password, this.workFactor);
        } finally {
            destroy();
        }
    }
}

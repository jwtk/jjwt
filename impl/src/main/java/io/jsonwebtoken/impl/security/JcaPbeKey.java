package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PbeKey;

import javax.crypto.interfaces.PBEKey;
import javax.security.auth.DestroyFailedException;

public class JcaPbeKey implements PbeKey {

    private final PBEKey jcaKey;

    public JcaPbeKey(PBEKey jcaKey) {
        this.jcaKey = Assert.notNull(jcaKey, "PBEKey cannot be null.");
    }

    @Override
    public char[] getPassword() {
        return this.jcaKey.getPassword();
    }

    @Override
    public int getWorkFactor() {
        return this.jcaKey.getIterationCount();
    }

    @Override
    public String getAlgorithm() {
        return this.jcaKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return this.jcaKey.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return this.jcaKey.getEncoded();
    }

    @Override
    public void destroy() throws DestroyFailedException {
        this.jcaKey.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return this.jcaKey.isDestroyed();
    }
}

package io.jsonwebtoken.impl;

import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

public class DefaultJwe<B> extends DefaultJwt<JweHeader, B> implements Jwe<B> {

    private final byte[] iv;
    private final byte[] aadTag;

    public DefaultJwe(JweHeader header, B body, byte[] iv, byte[] aadTag) {
        super(header, body);
        this.iv = Assert.notEmpty(iv, "Initialization vector cannot be null or empty.");
        this.aadTag = Assert.notEmpty(aadTag, "AAD tag cannot be null or empty.");
    }

    @Override
    public byte[] getInitializationVector() {
        return this.iv;
    }

    @Override
    public byte[] getAadTag() {
        return this.aadTag;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>)obj;
            return super.equals(jwe) &&
                Objects.nullSafeEquals(iv, jwe.getInitializationVector()) &&
                Objects.nullSafeEquals(aadTag, jwe.getAadTag());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getBody(), iv, aadTag);
    }
}

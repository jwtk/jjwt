package io.jsonwebtoken.impl;

import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

public class DefaultJwe<P> extends DefaultJwt<JweHeader, P> implements Jwe<P> {

    private final byte[] iv;
    private final byte[] aadTag;

    public DefaultJwe(JweHeader header, P body, byte[] iv, byte[] aadTag) {
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
    protected StringBuilder toStringBuilder() {
        StringBuilder sb = super.toStringBuilder();
        sb.append(",iv=").append(Encoders.BASE64URL.encode(this.iv));
        sb.append(",tag=").append(Encoders.BASE64URL.encode(this.aadTag));
        return sb;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>) obj;
            return super.equals(jwe) &&
                    Objects.nullSafeEquals(iv, jwe.getInitializationVector()) &&
                    Objects.nullSafeEquals(aadTag, jwe.getAadTag());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getPayload(), iv, aadTag);
    }
}

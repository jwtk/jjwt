package io.jsonwebtoken.impl;

import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.ProtectedJwt;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

import java.security.MessageDigest;

public class DefaultProtectedJwt<H extends ProtectedHeader, P> extends DefaultJwt<H, P> implements ProtectedJwt<H, P> {

    protected final byte[] digest;

    private final String digestName;

    public DefaultProtectedJwt(H header, P payload, byte[] digest, String digestName) {
        super(header, payload);
        this.digest = Assert.notEmpty(digest, "Digest byte array cannot be null or empty.");
        this.digestName = Assert.hasText(digestName, "digestName cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.digest.clone();
    }

    @Override
    protected StringBuilder toStringBuilder() {
        String b64Url = Encoders.BASE64URL.encode(this.digest);
        return super.toStringBuilder().append(',').append(this.digestName).append('=').append(b64Url);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof DefaultProtectedJwt) {
            DefaultProtectedJwt<?, ?> pjwt = (DefaultProtectedJwt<?, ?>) obj;
            return super.equals(pjwt) && MessageDigest.isEqual(this.digest, pjwt.digest);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(getHeader(), getPayload(), this.digest);
    }
}

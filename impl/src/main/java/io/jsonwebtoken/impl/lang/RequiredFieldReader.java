package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.security.JwkContext;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.MalformedKeyException;

public class RequiredFieldReader implements FieldReadable {

    private final FieldReadable src;

    public RequiredFieldReader(Header<?> header) {
        this(Assert.isInstanceOf(FieldReadable.class, header, "Header implementations must implement FieldReadable."));
    }

    public RequiredFieldReader(FieldReadable src) {
        this.src = Assert.notNull(src, "Source FieldReadable cannot be null.");
        Assert.isInstanceOf(Nameable.class, src, "FieldReadable implementations must implement Nameable.");
    }

    private String name() {
        return ((Nameable) this.src).getName();
    }

    private JwtException malformed(String msg) {
        if (this.src instanceof JwkContext || this.src instanceof Jwk) {
            return new MalformedKeyException(msg);
        } else {
            return new MalformedJwtException(msg);
        }
    }

    @Override
    public <T> T get(Field<T> field) {
        T value = this.src.get(field);
        if (value == null) {
            String msg = name() + " is missing required " + field + " value.";
            throw malformed(msg);
        }
        return value;
    }
}

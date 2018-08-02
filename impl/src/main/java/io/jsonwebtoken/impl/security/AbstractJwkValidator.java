package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.MalformedKeyException;

abstract class AbstractJwkValidator<T extends Jwk> implements JwkValidator<T> {

    private final String TYPE_VALUE;

    AbstractJwkValidator(String kty) {
        kty = Strings.clean(kty);
        Assert.notNull(kty);
        this.TYPE_VALUE = kty;
    }

    static void malformed(String msg) throws MalformedKeyException {
        throw new MalformedKeyException(msg);
    }

    @Override
    public final void validate(T jwk) throws KeyException {

        String type = jwk.getType();
        if (!Strings.hasText(type)) {
            malformed("JWKs must have a key type ('kty') property value.");
        }

        if (!TYPE_VALUE.equals(type)) {
            malformed("JWK does not have expected key type ('kty') value of '" +
                TYPE_VALUE + "'. Value found: " + type);
        }

        validateJwk(jwk);
    }

    abstract void validateJwk(T jwk) throws KeyException;
}

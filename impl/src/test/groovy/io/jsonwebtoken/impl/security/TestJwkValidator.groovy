package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.KeyException

class TestJwkValidator<T extends Jwk> extends AbstractJwkValidator<T> {

    T jwk;

    def TestJwkValidator(String kty="test") {
        super(kty)
    }

    @Override
    void validateJwk(T jwk) throws KeyException {
        this.jwk = jwk;
    }
}

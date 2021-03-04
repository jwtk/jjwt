package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.SymmetricJwk;

class SymmetricJwkValidator extends AbstractJwkValidator<SymmetricJwk> {

    SymmetricJwkValidator() {
        super(DefaultSymmetricJwk.TYPE_VALUE);
    }

    @Override
    void validateJwk(SymmetricJwk jwk) throws KeyException {

        String k = jwk.getK();
        if (!Strings.hasText(k)) {
            malformed("Symmetric JWK key value ('k' property) must be specified.");
        }

        //TODO: k length validation?
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.RsaJwk;

public class AbstractRsaJwkValidator<T extends RsaJwk> extends AbstractJwkValidator<T> {

    AbstractRsaJwkValidator() {
        super(AbstractRsaJwk.TYPE_VALUE);
    }

    @Override
    void validateJwk(T jwk) throws KeyException {

    }
}

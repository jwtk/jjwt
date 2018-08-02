package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SymmetricJwk;
import io.jsonwebtoken.security.SymmetricJwkBuilder;

final class DefaultSymmetricJwkBuilder extends AbstractJwkBuilder<SymmetricJwkBuilder, SymmetricJwk> implements SymmetricJwkBuilder {

    private static final JwkValidator<SymmetricJwk> VALIDATOR = new SymmetricJwkValidator();

    DefaultSymmetricJwkBuilder() {
        super(VALIDATOR);
    }

    @Override
    public SymmetricJwkBuilder setK(String k) {
        this.jwk.setK(k);
        return this;
    }

    @Override
    SymmetricJwk newJwk() {
        return new DefaultSymmetricJwk();
    }
}

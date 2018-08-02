package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PrivateEcJwk;
import io.jsonwebtoken.security.PrivateEcJwkBuilder;

class DefaultPrivateEcJwkBuilder extends AbstractEcJwkBuilder<PrivateEcJwkBuilder, PrivateEcJwk> implements PrivateEcJwkBuilder {

    private static final JwkValidator<PrivateEcJwk> VALIDATOR = new PrivateEcJwkValidator();

    DefaultPrivateEcJwkBuilder() {
        super(VALIDATOR);
    }

    @Override
    PrivateEcJwk newJwk() {
        return new DefaultPrivateEcJwk();
    }

    @Override
    public PrivateEcJwkBuilder setD(String d) {
        this.jwk.setD(d);
        return this;
    }
}

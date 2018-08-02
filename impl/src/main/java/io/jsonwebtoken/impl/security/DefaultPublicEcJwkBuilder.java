package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PublicEcJwk;
import io.jsonwebtoken.security.PublicEcJwkBuilder;

class DefaultPublicEcJwkBuilder extends AbstractEcJwkBuilder<PublicEcJwkBuilder, PublicEcJwk> implements PublicEcJwkBuilder {

    private static final JwkValidator<PublicEcJwk> VALIDATOR = new AbstractEcJwkValidator<PublicEcJwk>() {
        @Override
        protected void validateEcJwk(PublicEcJwk jwk) {
            //nothing additional to do
        }
    };

    DefaultPublicEcJwkBuilder() {
        super(VALIDATOR);
    }

    @Override
    PublicEcJwk newJwk() {
        return new DefaultPublicEcJwk();
    }
}

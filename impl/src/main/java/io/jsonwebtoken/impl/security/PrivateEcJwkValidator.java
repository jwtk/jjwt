package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.PrivateEcJwk;

class PrivateEcJwkValidator extends AbstractEcJwkValidator<PrivateEcJwk> {

    @Override
    void validateEcJwk(PrivateEcJwk jwk) {
        if (!Strings.hasText(jwk.getD())) {
            String msg = "Private EC JWK private key ('d' property') must be specified.";
            throw new MalformedKeyException(msg);
        }

        //TODO: RFC octet length validation for d value
    }
}

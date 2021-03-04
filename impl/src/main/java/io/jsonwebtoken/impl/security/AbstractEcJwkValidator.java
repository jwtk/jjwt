package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.CurveId;
import io.jsonwebtoken.security.CurveIds;
import io.jsonwebtoken.security.EcJwk;
import io.jsonwebtoken.security.KeyException;

abstract class AbstractEcJwkValidator<T extends EcJwk> extends AbstractJwkValidator<T> {

    AbstractEcJwkValidator() {
        super(AbstractEcJwk.TYPE_VALUE);
    }

    @Override
    final void validateJwk(T jwk) throws KeyException {

        CurveId curveId = jwk.getCurveId();
        if (curveId == null) { // https://tools.ietf.org/html/rfc7518#section-6.2.1
            malformed("EC JWK curve id ('crv' property) must be specified.");
        }

        String x = jwk.getX();
        if (!Strings.hasText(x)) { // https://tools.ietf.org/html/rfc7518#section-6.2.1
            malformed("EC JWK x coordinate ('x' property) must be specified.");
        }

        // https://tools.ietf.org/html/rfc7518#section-6.2.1 (last sentence):
        if (CurveIds.isStandard(curveId) && !Strings.hasText(jwk.getY())) {
            malformed(curveId + " EC JWK y coordinate ('y' property) must be specified.");
        }

        //TODO: RFC length validation for x and y values

        validateEcJwk(jwk);
    }

    abstract void validateEcJwk(T jwk);
}

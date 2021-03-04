package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilderFactory {

    EcJwkBuilderFactory ellipticCurve();

    SymmetricJwkBuilder symmetric();

}

package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwk<T extends EcJwk> extends Jwk<T>, EcJwkMutator<T> {

    CurveId getCurveId();

    String getX();

    String getY();
}

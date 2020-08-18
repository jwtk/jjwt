package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwk<T extends EcJwk<T>> extends Jwk<T>, EcJwkMutator<T> {

    CurveId getCurveId();

    String getX();

    String getY();
}

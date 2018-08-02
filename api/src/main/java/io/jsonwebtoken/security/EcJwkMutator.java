package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwkMutator<T extends EcJwkMutator> extends JwkMutator<T> {

    T setCurveId(CurveId curveId);

    T setX(String x);

    T setY(String y);
}

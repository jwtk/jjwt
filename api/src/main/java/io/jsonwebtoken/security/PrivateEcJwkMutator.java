package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateEcJwkMutator<T extends PrivateEcJwkMutator> extends EcJwkMutator<T> {

    T setD(String d);
}

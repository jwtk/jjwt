package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricJwkMutator<T extends SymmetricJwkMutator<T>> extends JwkMutator<T> {

    T setK(String k);
}

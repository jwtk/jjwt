package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface RsaJwkMutator<T extends RsaJwkMutator<T>> extends JwkMutator<T> {

    T setModulus(String n);

    T setExponent(String e);
}

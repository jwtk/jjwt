package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilder<K extends Jwk<K>, T extends JwkBuilder<K,T>> extends JwkMutator<T> {

    K build();

}

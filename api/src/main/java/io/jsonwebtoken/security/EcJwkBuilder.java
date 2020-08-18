package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwkBuilder<K extends EcJwk<K>, T extends EcJwkBuilder<K,T>> extends JwkBuilder<K, T>, EcJwkMutator<T> {
}

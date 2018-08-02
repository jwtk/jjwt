package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwkBuilder<T extends EcJwkBuilder, K extends EcJwk> extends JwkBuilder<T, K>, EcJwkMutator<T> {
}

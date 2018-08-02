package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilder<T extends JwkBuilder, K extends Jwk> extends JwkMutator<T> {

    K build();

}

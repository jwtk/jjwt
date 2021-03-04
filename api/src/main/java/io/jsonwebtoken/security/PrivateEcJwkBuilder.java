package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateEcJwkBuilder extends EcJwkBuilder<PrivateEcJwk, PrivateEcJwkBuilder> {

    PrivateEcJwkBuilder setD(String d);
}

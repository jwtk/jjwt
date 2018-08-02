package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateEcJwkBuilder extends EcJwkBuilder<PrivateEcJwkBuilder, PrivateEcJwk> {

    PrivateEcJwkBuilder setD(String d);
}

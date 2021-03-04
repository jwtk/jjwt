package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateEcJwk extends EcJwk<PrivateEcJwk>, PrivateEcJwkMutator<PrivateEcJwk> {

    String getD();
}

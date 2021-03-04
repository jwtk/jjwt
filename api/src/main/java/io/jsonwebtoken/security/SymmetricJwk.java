package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricJwk extends Jwk<SymmetricJwk>, SymmetricJwkMutator<SymmetricJwk> {

    String getK();
}

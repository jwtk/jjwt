package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkRsaPrimeInfoBuilder extends JwkRsaPrimeInfoMutator<JwkRsaPrimeInfoBuilder> {

    JwkRsaPrimeInfo build();
}

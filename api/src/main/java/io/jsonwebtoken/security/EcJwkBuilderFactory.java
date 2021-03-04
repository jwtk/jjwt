package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EcJwkBuilderFactory {

    PublicEcJwkBuilder publicKey();

    PrivateEcJwkBuilder privateKey();
}

package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface IvEncryptionResult extends EncryptionResult, InitializationVectorSource {

    byte[] compact();
}

package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadDecryptionRequest extends SymmetricAeadRequest, InitializationVectorSource, AuthenticationTagSource {
}

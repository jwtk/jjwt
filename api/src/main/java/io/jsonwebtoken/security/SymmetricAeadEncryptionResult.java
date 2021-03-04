package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadEncryptionResult extends PayloadSupplier<byte[]>, AuthenticationTagSource, InitializationVectorSource {
}

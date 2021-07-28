package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AeadResult extends PayloadSupplier<byte[]>, AuthenticationTagSource, InitializationVectorSource {
}

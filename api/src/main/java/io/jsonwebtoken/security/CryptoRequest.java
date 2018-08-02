package io.jsonwebtoken.security;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface CryptoRequest<T, K extends Key> extends CryptoMessage<T> {

    /**
     * Returns the JCA provider that should be used for cryptographic operations during the request or
     * {@code null} if the JCA subsystem preferred provider should be used.
     *
     * @return the JCA provider that should be used for cryptographic operations during the request or
     * {@code null} if the JCA subsystem preferred provider should be used.
     */
    Provider getProvider();

    /**
     * Returns the {@code SecureRandom} to use when performing cryptographic operations during the request, or
     * {@code null} if a default {@link SecureRandom} should be used.
     *
     * @return the {@code SecureRandom} to use when performing cryptographic operations during the request, or
     * {@code null} if a default {@link SecureRandom} should be used.
     */
    SecureRandom getSecureRandom();

    /**
     * Returns the key to use for signing, wrapping, encryption or decryption depending on the type of request.
     *
     * @return the key to use for signing, wrapping, encryption or decryption depending on the type of request.
     */
    K getKey();
}

package io.jsonwebtoken.security;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SecurityRequest {

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
}

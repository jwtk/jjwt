package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricKeyAlgorithm {

    /**
     * Creates and returns a new secure-random key with a length sufficient to be used by this Algorithm.
     *
     * @return a new secure-random key with a length sufficient to be used by this Algorithm.
     */
    SecretKey generateKey();
}

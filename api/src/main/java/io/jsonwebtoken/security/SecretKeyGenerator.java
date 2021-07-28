package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretKeyGenerator {

    /**
     * Creates and returns a new secure-random key with a length sufficient to be used by the associated Algorithm.
     *
     * @return a new secure-random key with a length sufficient to be used by the associated Algorithm.
     */
    SecretKey generateKey();
}

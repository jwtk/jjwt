package io.jsonwebtoken.security;

import java.security.KeyPair;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricKeyGenerator {

    /**
     * Generates a new secure-random key pair with a key length suitable for the associated Algorithm.
     *
     * @return a new secure-random key pair with a key length suitable for the associated Algorithm.
     */
    KeyPair generateKeyPair();
}

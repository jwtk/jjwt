package io.jsonwebtoken.security;

import java.security.KeyPair;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricKeyAlgorithm {

    /**
     * Generates a new secure-random key pair with a key length suitable for this Algorithm.
     *
     * @return a new secure-random key pair with a key length suitable for this Algorithm.
     */
    KeyPair generateKeyPair();
}

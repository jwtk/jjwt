package io.jsonwebtoken.security;

import io.jsonwebtoken.SignatureAlgorithm;

import java.security.KeyPair;

public interface KeyPairGenerator {
    boolean supports(SignatureAlgorithm alg);

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified {@link SignatureAlgorithm} using
     * JJWT's default SecureRandom instance.
     *
     * @param alg the algorithm indicating strength
     * @return a new secure-randomly generated key pair of sufficient strength for the specified {@link
     * SignatureAlgorithm}.
     */
    KeyPair generateKeyPair(SignatureAlgorithm alg);
}

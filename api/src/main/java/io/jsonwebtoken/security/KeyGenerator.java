package io.jsonwebtoken.security;

import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;

public interface KeyGenerator {
    boolean supports(SignatureAlgorithm alg);

    /**
     * Generates a new secure-random secret key of a length suitable for creating and verifying HMAC signatures
     * according to the specified {@code SignatureAlgorithm}.
     *
     * @param alg the desired signature algorithm
     * @return a new secure-random secret key of a length suitable for creating and verifying HMAC signatures according
     * to the specified {@code SignatureAlgorithm}.
     */
    SecretKey generateKey(SignatureAlgorithm alg);
}

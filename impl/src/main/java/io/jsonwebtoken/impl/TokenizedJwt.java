package io.jsonwebtoken.impl;

public interface TokenizedJwt {

    /**
     * Protected header.
     * @return protected header.
     */
    String getProtected();

    /**
     * Payload for JWS, Ciphertext for JWE
     */
    String getBody();

    /**
     * Signature for JWS, AAD Tag for JWE.
     */
    String getDigest();
}

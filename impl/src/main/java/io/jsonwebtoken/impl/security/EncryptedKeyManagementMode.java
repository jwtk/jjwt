package io.jsonwebtoken.impl.security;

/**
 * A {@code KeyManagementMode} that encrypts the JWE encryption key itself.  This is used when embedding the content
 * encryption key in the JWE as an encrypted value.  This technique allows 1) two or more parties to use the same
 * randomly generated key and 2) have an encrypted form of that key specific to each party, ensuring only intended
 * recipients may access the random key.  This tends to also be a faster approach since an asymmetric key algorithm
 * (which can be slow) can be used to encrypt just a key and a symmetric key (which is generally faster) can be used
 * to encrypt the main (larger) payload/claims.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptedKeyManagementMode extends KeyManagementMode {

    /**
     * Encrypts the key represented by the specified request.
     * @param request they key request
     * @return the encrypted content encryption key.
     */
    byte[] encryptKey(EncryptKeyRequest request);

}

package io.jsonwebtoken.security;

import io.jsonwebtoken.JweHeader;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface DecryptionKeyResolver {

    /**
     * Returns the decryption key that should be used to decrypt a corresponding JWE's Ciphertext (payload).
     *
     * @param header the JWE header to inspect to determine which decryption key should be used
     * @return the decryption key that should be used to decrypt a corresponding JWE's Ciphertext (payload).
     */
    Key resolveDecryptionKey(JweHeader header);
}

package io.jsonwebtoken;

import java.security.Key;

/**
 * @since 0.7.0
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

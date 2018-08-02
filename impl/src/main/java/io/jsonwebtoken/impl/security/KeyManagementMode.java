package io.jsonwebtoken.impl.security;

import javax.crypto.SecretKey;

/**
 * A Key Management Mode determines the content encryption key to use to encrypt a JWE's payload.
 * <p>
 * If a mode encrypts the encryption key itself for one or more recipients, that mode would implement the
 * {@link EncryptedKeyManagementMode} instead of this interface.
 *
 * @see EncryptedKeyManagementMode
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyManagementMode {

    /**
     * Returns the key used to encrypt the JWE payload.
     *
     * @return the key used to encrypt the JWE payload.
     */
    SecretKey getKey(GetKeyRequest request);
}

package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeySupplier<K extends Key> {

    /**
     * Returns the key to use for signing, wrapping, encryption or decryption depending on the type of operation.
     *
     * @return the key to use for signing, wrapping, encryption or decryption depending on the type of operation.
     */
    K getKey();
}

package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface InitializationVectorSource {

    /**
     * Returns the secure-random initialization vector used during encryption that must be presented in order
     * to decrypt.
     *
     * @return the secure-random initialization vector used during encryption that must be presented in order
     * to decrypt.
     */
    byte[] getInitializationVector();
}

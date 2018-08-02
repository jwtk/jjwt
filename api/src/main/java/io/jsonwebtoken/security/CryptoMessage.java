package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface CryptoMessage<T> {

    T getData(); //plaintext, ciphertext, or Key for key wrap algorithms

}

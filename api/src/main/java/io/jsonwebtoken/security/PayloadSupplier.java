package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PayloadSupplier<T> {

    T getPayload(); //plaintext, ciphertext, or Key to be wrapped

}

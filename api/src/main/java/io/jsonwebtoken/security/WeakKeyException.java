package io.jsonwebtoken.security;

/**
 * @since 0.10.0
 */
public class WeakKeyException extends InvalidKeyException {

    public WeakKeyException(String message) {
        super(message);
    }
}

package io.jsonwebtoken.security;

/**
 * @since 0.10.0
 */
public class InvalidKeyException extends KeyException {

    public InvalidKeyException(String message) {
        super(message);
    }
}

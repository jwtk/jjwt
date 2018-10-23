package io.jsonwebtoken.security;

import io.jsonwebtoken.JwtException;

/**
 * @since 0.10.0
 */
public class SecurityException extends JwtException {

    public SecurityException(String message) {
        super(message);
    }

    public SecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}

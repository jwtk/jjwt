package io.jsonwebtoken.io;

import io.jsonwebtoken.JwtException;

/**
 * @since 0.10.0
 */
public class IOException extends JwtException {

    public IOException(String msg) {
        super(msg);
    }

    public IOException(String message, Throwable cause) {
        super(message, cause);
    }
}

package io.jsonwebtoken.io;

import io.jsonwebtoken.JwtException;

public class IOException extends JwtException {

    public IOException(String message, Throwable cause) {
        super(message, cause);
    }
}

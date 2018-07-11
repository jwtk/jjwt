package io.jsonwebtoken.io;

import io.jsonwebtoken.JwtException;

public class IOException extends JwtException {

    public IOException(String msg) {
        super(msg);
    }

    public IOException(String message, Throwable cause) {
        super(message, cause);
    }
}

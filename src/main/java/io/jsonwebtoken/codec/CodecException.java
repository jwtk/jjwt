package io.jsonwebtoken.codec;

import io.jsonwebtoken.JwtException;

/**
 * @since 0.10.0
 */
public class CodecException extends JwtException {

    public CodecException(String message, Throwable cause) {
        super(message, cause);
    }
}

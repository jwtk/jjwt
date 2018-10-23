package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public class DecodingException extends CodecException {

    public DecodingException(String message) {
        super(message);
    }

    public DecodingException(String message, Throwable cause) {
        super(message, cause);
    }
}

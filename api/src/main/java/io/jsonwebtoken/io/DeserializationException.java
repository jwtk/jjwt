package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public class DeserializationException extends SerialException {

    public DeserializationException(String msg) {
        super(msg);
    }

    public DeserializationException(String message, Throwable cause) {
        super(message, cause);
    }
}

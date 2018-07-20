package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public class SerializationException extends SerialException {

    public SerializationException(String msg) {
        super(msg);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}

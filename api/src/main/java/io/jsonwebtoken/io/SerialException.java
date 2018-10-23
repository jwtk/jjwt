package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public class SerialException extends IOException {

    public SerialException(String msg) {
        super(msg);
    }

    public SerialException(String message, Throwable cause) {
        super(message, cause);
    }
}

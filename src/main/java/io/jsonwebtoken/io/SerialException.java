package io.jsonwebtoken.io;

public class SerialException extends IOException {

    public SerialException(String msg) {
        super(msg);
    }

    public SerialException(String message, Throwable cause) {
        super(message, cause);
    }
}

package io.jsonwebtoken.io;

public class DeserializationException extends SerialException {

    public DeserializationException(String msg) {
        super(msg);
    }

    public DeserializationException(String message, Throwable cause) {
        super(message, cause);
    }
}

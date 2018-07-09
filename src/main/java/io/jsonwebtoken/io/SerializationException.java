package io.jsonwebtoken.io;

public class SerializationException extends SerialException {

    public SerializationException(String msg) {
        super(msg);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}

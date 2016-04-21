package io.jsonwebtoken.impl.serialization;

import io.jsonwebtoken.JwtException;

public class SerializationException extends JwtException {

    public SerializationException(String message, Throwable e) {
        super(message, e);
    }

}

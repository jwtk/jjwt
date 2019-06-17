package io.jsonwebtoken.lang;

import io.jsonwebtoken.JwtException;

/**
 * Exception indicating that no implementation of an jjwt-api SPI was found on the classpath.
 */
public class ImplementationNotFoundException extends JwtException {

    ImplementationNotFoundException(final String message) {
        super(message);
    }
}

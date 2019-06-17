package io.jsonwebtoken.factory;

import io.jsonwebtoken.JwtException;

/**
 * Exception indicating that no implementation of jjwt-api was found on the classpath.
 */
public class ImplementationNotFoundException extends JwtException {

    ImplementationNotFoundException(final String message) {
        super(message);
    }
}

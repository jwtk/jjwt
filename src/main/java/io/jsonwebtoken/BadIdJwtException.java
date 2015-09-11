package io.jsonwebtoken;

public class BadIdJwtException extends ClaimJwtException {
    public BadIdJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public BadIdJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}

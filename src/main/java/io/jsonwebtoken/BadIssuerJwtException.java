package io.jsonwebtoken;

public class BadIssuerJwtException extends ClaimJwtException {
    public BadIssuerJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public BadIssuerJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}

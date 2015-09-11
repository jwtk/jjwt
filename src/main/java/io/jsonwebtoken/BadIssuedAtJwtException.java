package io.jsonwebtoken;

public class BadIssuedAtJwtException extends ClaimJwtException {
    public BadIssuedAtJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public BadIssuedAtJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}

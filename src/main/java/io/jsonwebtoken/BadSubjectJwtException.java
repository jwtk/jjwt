package io.jsonwebtoken;

public class BadSubjectJwtException extends ClaimJwtException {
    public BadSubjectJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public BadSubjectJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}

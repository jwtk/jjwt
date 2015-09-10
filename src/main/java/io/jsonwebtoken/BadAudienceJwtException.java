package io.jsonwebtoken;

public class BadAudienceJwtException extends ClaimJwtException {
    public BadAudienceJwtException(Header header, Claims claims, String message) {
        super(header, claims, message);
    }

    public BadAudienceJwtException(Header header, Claims claims, String message, Throwable cause) {
        super(header, claims, message, cause);
    }
}

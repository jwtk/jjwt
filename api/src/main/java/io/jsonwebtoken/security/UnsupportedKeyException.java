package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class UnsupportedKeyException extends KeyException {

    public UnsupportedKeyException(String message) {
        super(message);
    }

    public UnsupportedKeyException(String msg, Exception cause) {
        super(msg, cause);
    }
}

package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class MalformedKeyException extends InvalidKeyException {

    public MalformedKeyException(String message) {
        super(message);
    }

    public MalformedKeyException(String msg, Exception cause) {
        super(msg, cause);
    }
}

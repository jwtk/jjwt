package io.jsonwebtoken;

/**
 * @param <B> payload type
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwe<B> extends Jwt<JweHeader,B> {

    byte[] getInitializationVector();

    byte[] getAadTag();
}

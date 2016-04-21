package io.jsonwebtoken;

public interface Jwe<B> extends Jwt<JweHeader,B> {

    byte[] getInitializationVector();

    byte[] getAadTag();
}

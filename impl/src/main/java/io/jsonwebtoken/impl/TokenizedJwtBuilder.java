package io.jsonwebtoken.impl;

public interface TokenizedJwtBuilder {

    TokenizedJwtBuilder append(String token);

    <T extends TokenizedJwt> T build();

}

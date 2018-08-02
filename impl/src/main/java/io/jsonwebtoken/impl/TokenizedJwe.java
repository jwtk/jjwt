package io.jsonwebtoken.impl;

public interface TokenizedJwe extends TokenizedJwt {

    String getEncryptedKey();

    String getIv();
}

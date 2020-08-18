package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;

import java.util.Map;

class DefaultTokenizedJwe extends DefaultTokenizedJwt implements TokenizedJwe {

    private final String encryptedKey;
    private final String iv;

    DefaultTokenizedJwe(String protectedHeader, String body, String digest, String encryptedKey, String iv) {
        super(protectedHeader, body, digest);
        this.encryptedKey = encryptedKey;
        this.iv = iv;
    }

    @Override
    public String getEncryptedKey() {
        return this.encryptedKey;
    }

    @Override
    public String getIv() {
        return this.iv;
    }

    @Override
    public Header<?> createHeader(Map<String, ?> m) {
        return new DefaultJweHeader(m);
    }
}

package io.jsonwebtoken.impl;

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
}

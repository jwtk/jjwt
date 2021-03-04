package io.jsonwebtoken.impl;

class DefaultTokenizedJwt implements TokenizedJwt {

    private final String protectedHeader;
    private final String body;
    private final String digest;

    DefaultTokenizedJwt(String protectedHeader, String body, String digest) {
        this.protectedHeader = protectedHeader;
        this.body = body;
        this.digest = digest;
    }

    @Override
    public String getProtected() {
        return this.protectedHeader;
    }

    @Override
    public String getBody() {
        return this.body;
    }

    @Override
    public String getDigest() {
        return this.digest;
    }
}

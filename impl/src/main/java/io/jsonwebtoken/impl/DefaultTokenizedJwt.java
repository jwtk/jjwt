package io.jsonwebtoken.impl;


import io.jsonwebtoken.Header;
import io.jsonwebtoken.lang.Strings;

import java.util.Map;

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

    @Override
    public Header<?> createHeader(Map<String, ?> m) {
        if (Strings.hasText(getDigest())) {
            return new DefaultJwsHeader(m);
        }
        //noinspection unchecked
        return new DefaultHeader(m);
    }
}

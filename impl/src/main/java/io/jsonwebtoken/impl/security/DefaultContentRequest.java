package io.jsonwebtoken.impl.security;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultContentRequest extends DefaultRequest implements ContentRequest {

    private final byte[] content;

    public DefaultContentRequest(Provider provider, SecureRandom secureRandom, byte[] content) {
        super(provider, secureRandom);
        this.content = content;
    }

    @Override
    public byte[] getContent() {
        return this.content;
    }
}

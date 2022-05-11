package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Request;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultRequest implements Request {

    private final Provider provider;
    private final SecureRandom secureRandom;

    public DefaultRequest(Provider provider, SecureRandom secureRandom) {
        this.provider = provider;
        this.secureRandom = secureRandom;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.SecurityRequest;

import java.security.Provider;
import java.security.SecureRandom;

abstract class AbstractSecurityRequest implements SecurityRequest {

    private final Provider provider;
    private final SecureRandom secureRandom;

    public AbstractSecurityRequest(Provider provider, SecureRandom secureRandom) {
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

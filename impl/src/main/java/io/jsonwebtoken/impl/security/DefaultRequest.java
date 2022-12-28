package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Request;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultRequest<T> extends DefaultMessage<T> implements Request<T> {

    private final Provider provider;
    private final SecureRandom secureRandom;

    public DefaultRequest(T payload, Provider provider, SecureRandom secureRandom) {
        super(payload);
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

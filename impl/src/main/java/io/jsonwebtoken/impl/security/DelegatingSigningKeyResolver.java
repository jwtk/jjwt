package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResolver;

import java.security.Key;

public class DelegatingSigningKeyResolver implements SigningKeyResolver {

    private final KeyResolver keyResolver;

    public DelegatingSigningKeyResolver(KeyResolver keyResolver) {
        this.keyResolver = Assert.notNull(keyResolver, "KeyResolver cannot be null.");
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return this.keyResolver.resolveKey(header);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return this.keyResolver.resolveKey(header);
    }
}

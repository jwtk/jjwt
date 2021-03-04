package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.lang.Assert;

import java.security.Key;

//TODO: delete when removing SigningKeyResolver
public class StaticSigningKeyResolver implements SigningKeyResolver {

    private final Key key;

    public StaticSigningKeyResolver(Key key) {
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return this.key;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return this.key;
    }
}

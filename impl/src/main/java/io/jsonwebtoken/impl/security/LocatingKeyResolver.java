package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.lang.Assert;

import java.security.Key;

@SuppressWarnings("deprecation") // TODO: delete this class for 1.0
public class LocatingKeyResolver implements SigningKeyResolver {

    private final Locator<? extends Key> locator;

    public LocatingKeyResolver(Locator<? extends Key> locator) {
        this.locator = Assert.notNull(locator, "Locator cannot be null.");
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return this.locator.locate(header);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, byte[] payload) {
        return this.locator.locate(header);
    }
}

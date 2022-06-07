package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.lang.Function;

import java.security.Key;

@SuppressWarnings("deprecation")
public class ConstantKeyLocator extends LocatorAdapter<Key> implements SigningKeyResolver, Function<Header<?>, Key> {

    private final Key jwsKey;
    private final Key jweKey;

    public ConstantKeyLocator(Key jwsKey, Key jweKey) {
        this.jwsKey = jwsKey;
        this.jweKey = jweKey;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return locate(header);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, byte[] content) {
        return locate(header);
    }

    @Override
    protected Key locate(JwsHeader header) {
        return this.jwsKey;
    }

    @Override
    protected Key locate(JweHeader header) {
        return this.jweKey;
    }

    @Override
    public Key apply(Header<?> header) {
        return locate(header);
    }
}

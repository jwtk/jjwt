package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.security.LocatorAdapter;

import java.security.Key;

@SuppressWarnings("deprecation")
public class ConstantKeyLocator<H extends Header<H>> extends LocatorAdapter<H, Key> implements SigningKeyResolver, Function<H, Key> {

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
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
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
    public Key apply(H header) {
        return locate(header);
    }
}

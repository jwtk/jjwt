package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Jwk;

import java.security.Key;

public class DefaultJwkFactory<K extends Key, J extends Jwk<K>> implements JwkFactory<K,J> {

    @Override
    public J createJwk(JwkContext<K> ctx) {
        return null;
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Jwk;

import java.security.Key;

public interface JwkFactory<K extends Key, J extends Jwk<K>> {

    J createJwk(JwkContext<K> ctx);
}

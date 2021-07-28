package io.jsonwebtoken.impl.security;

public interface KeyUseStrategy {

    //TODO: change argument to have more information?
    String toJwkValue(KeyUsage keyUses);
}

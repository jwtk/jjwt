package io.jsonwebtoken.impl.security;

//TODO: Make a non-impl concept?
public interface KeyUseStrategy {

    //TODO: change argument to have more information?
    String toJwkValue(KeyUsage keyUses);
}

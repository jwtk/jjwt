package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyException;

import java.security.Key;
import java.util.Map;

public interface JwkParser {

    Key parse(String json) throws KeyException;

    Key parse(Map<String,?> jwkMap) throws KeyException;

    Jwk parseToJwk(String json) throws KeyException;

    Jwk parseToJwk(Map<String,?> jwkMap) throws KeyException;

}

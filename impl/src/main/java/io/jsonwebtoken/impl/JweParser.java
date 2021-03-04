package io.jsonwebtoken.impl;

import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;

public interface JweParser {

    Jwe<?> parse(String jwt) throws JwtException;
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyException;

public interface JwkValidator<T extends Jwk> {

    void validate(T jwk) throws KeyException;
}

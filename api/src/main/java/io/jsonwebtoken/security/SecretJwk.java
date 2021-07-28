package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

public interface SecretJwk<V> extends Jwk<V, SecretKey> {
}

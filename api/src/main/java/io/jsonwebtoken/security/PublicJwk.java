package io.jsonwebtoken.security;

import java.security.PublicKey;

public interface PublicJwk<V, K extends PublicKey> extends AsymmetricJwk<V, K> {
}

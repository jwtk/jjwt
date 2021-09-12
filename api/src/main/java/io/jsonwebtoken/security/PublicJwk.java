package io.jsonwebtoken.security;

import java.security.PublicKey;

public interface PublicJwk<K extends PublicKey> extends AsymmetricJwk<K> {
}

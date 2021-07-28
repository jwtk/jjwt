package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPrivateJwk<V> extends PrivateJwk<V, RSAPrivateKey, RSAPublicKey, RsaPublicJwk<V>> {
}

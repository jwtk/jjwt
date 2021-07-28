package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPrivateJwkBuilder<V> extends PrivateJwkBuilder<RSAPrivateKey, RSAPublicKey, RsaPublicJwk<V>, RsaPrivateJwk<V>, RsaPrivateJwkBuilder<V>> {
}

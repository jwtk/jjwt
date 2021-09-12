package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPrivateJwkBuilder extends PrivateJwkBuilder<RSAPrivateKey, RSAPublicKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder> {
}

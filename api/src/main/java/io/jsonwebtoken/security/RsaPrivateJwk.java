package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPrivateJwk extends PrivateJwk<RSAPrivateKey, RSAPublicKey, RsaPublicJwk> {
}

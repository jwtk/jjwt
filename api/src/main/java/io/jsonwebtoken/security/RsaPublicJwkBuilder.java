package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPublicJwkBuilder extends PublicJwkBuilder<RSAPublicKey, RSAPrivateKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder, RsaPublicJwkBuilder> {

}

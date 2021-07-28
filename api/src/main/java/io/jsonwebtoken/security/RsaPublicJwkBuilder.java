package io.jsonwebtoken.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface RsaPublicJwkBuilder<V> extends PublicJwkBuilder<RSAPublicKey, RSAPrivateKey, RsaPublicJwk<V>, RsaPrivateJwk<V>, RsaPrivateJwkBuilder<V>, RsaPublicJwkBuilder<V>> {

}

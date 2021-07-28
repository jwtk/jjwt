package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPublicJwkBuilder<V> extends PublicJwkBuilder<ECPublicKey, ECPrivateKey, EcPublicJwk<V>, EcPrivateJwk<V>, EcPrivateJwkBuilder<V>, EcPublicJwkBuilder<V>> {
}

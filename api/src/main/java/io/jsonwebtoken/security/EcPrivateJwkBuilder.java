package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPrivateJwkBuilder<V> extends PrivateJwkBuilder<ECPrivateKey, ECPublicKey, EcPublicJwk<V>, EcPrivateJwk<V>, EcPrivateJwkBuilder<V>> {
}

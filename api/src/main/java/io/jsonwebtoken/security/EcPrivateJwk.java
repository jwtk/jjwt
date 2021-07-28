package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPrivateJwk<V> extends PrivateJwk<V, ECPrivateKey, ECPublicKey, EcPublicJwk<V>> {
}

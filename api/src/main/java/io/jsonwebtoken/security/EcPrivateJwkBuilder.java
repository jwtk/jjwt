package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPrivateJwkBuilder extends PrivateJwkBuilder<ECPrivateKey, ECPublicKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder> {
}

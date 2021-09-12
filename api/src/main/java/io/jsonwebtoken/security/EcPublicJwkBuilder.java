package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPublicJwkBuilder extends PublicJwkBuilder<ECPublicKey, ECPrivateKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder, EcPublicJwkBuilder> {
}

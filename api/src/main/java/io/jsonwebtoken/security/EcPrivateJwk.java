package io.jsonwebtoken.security;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface EcPrivateJwk extends PrivateJwk<ECPrivateKey, ECPublicKey, EcPublicJwk> {
}

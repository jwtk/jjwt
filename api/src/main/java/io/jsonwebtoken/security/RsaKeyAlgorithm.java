package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

public interface RsaKeyAlgorithm<EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> extends KeyAlgorithm<EK, DK> {
}

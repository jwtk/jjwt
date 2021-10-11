package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;

public interface EcKeyAlgorithm<E extends ECKey & PublicKey, D extends ECKey & PrivateKey> extends KeyAlgorithm<E, D> {
}

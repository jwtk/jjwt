package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface PublicJwkBuilder<K extends PublicKey, L extends PrivateKey, J extends PublicJwk<K>, M extends PrivateJwk<L, K, J>, P extends PrivateJwkBuilder<L, K, J, M, P>, T extends PublicJwkBuilder<K, L, J, M, P, T>> extends AsymmetricJwkBuilder<K, J, T> {

    P setPrivateKey(L privateKey);
}

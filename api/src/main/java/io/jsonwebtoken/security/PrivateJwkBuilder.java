package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface PrivateJwkBuilder<K extends PrivateKey, L extends PublicKey, J extends PublicJwk<?, L>, M extends PrivateJwk<?, K, L, J>, T extends PrivateJwkBuilder<K, L, J, M, T>> extends AsymmetricJwkMutator<T>, JwkBuilder<K, M, T> {

    T setPublicKey(L publicKey);
}

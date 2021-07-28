package io.jsonwebtoken.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface PrivateJwk<V, K extends PrivateKey, L extends PublicKey, M extends PublicJwk<V, L>> extends AsymmetricJwk<V, K> {

    M toPublicJwk();

    KeyPair toKeyPair();

}

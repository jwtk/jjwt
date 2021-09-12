package io.jsonwebtoken.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface PrivateJwk<K extends PrivateKey, L extends PublicKey, M extends PublicJwk<L>> extends AsymmetricJwk<K> {

    M toPublicJwk();

    KeyPair toKeyPair();

}

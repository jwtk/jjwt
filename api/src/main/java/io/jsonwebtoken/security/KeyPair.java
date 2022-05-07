package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPair<A extends PublicKey, B extends PrivateKey> {

    A getPublic();

    B getPrivate();

    java.security.KeyPair toJdkKeyPair();
}

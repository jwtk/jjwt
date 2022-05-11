package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Generics-capable and type-safe alternative to {@link java.security.KeyPair}.  Instances may be
 * converted to {@link java.security.KeyPair} if desired via {@link #toJavaKeyPair()}.
 *
 * @param <A> The type of {@link PublicKey} in the key pair.
 * @param <B> The type of {@link PrivateKey} in the key pair.
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPair<A extends PublicKey, B extends PrivateKey> {

    /**
     * Returns the pair's public key.
     *
     * @return the pair's public key.
     */
    A getPublic();

    /**
     * Returns the pair's private key.
     *
     * @return the pair's private key.
     */
    B getPrivate();

    /**
     * Returns this instance as a {@link java.security.KeyPair} instance.
     *
     * @return this instance as a {@link java.security.KeyPair} instance.
     */
    java.security.KeyPair toJavaKeyPair();
}

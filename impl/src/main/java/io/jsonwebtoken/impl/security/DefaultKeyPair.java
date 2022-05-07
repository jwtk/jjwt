package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPair;

import java.security.PrivateKey;
import java.security.PublicKey;

public class DefaultKeyPair<A extends PublicKey, B extends PrivateKey> implements KeyPair<A, B> {

    private final A publicKey;
    private final B privateKey;

    private final java.security.KeyPair jdkPair;

    public DefaultKeyPair(A publicKey, B privateKey) {
        this.publicKey = Assert.notNull(publicKey, "PublicKey argument cannot be null.");
        this.privateKey = Assert.notNull(privateKey, "PrivateKey argument cannot be null.");
        this.jdkPair = new java.security.KeyPair(this.publicKey, this.privateKey);
    }

    @Override
    public A getPublic() {
        return this.publicKey;
    }

    @Override
    public B getPrivate() {
        return this.privateKey;
    }

    @Override
    public java.security.KeyPair toJdkKeyPair() {
        return this.jdkPair;
    }
}

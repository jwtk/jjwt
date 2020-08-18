package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

abstract class AbstractPrivateJwk<K extends PrivateKey, L extends PublicKey, M extends PublicJwk<L>>
    extends AbstractAsymmetricJwk<K> implements PrivateJwk<K, L, M> {

    private final M publicJwk;
    private final KeyPair keyPair;

    AbstractPrivateJwk(JwkContext<K> ctx, M pubJwk) {
        super(ctx);
        this.publicJwk = Assert.notNull(pubJwk, "PublicJwk instance cannot be null.");
        L publicKey = Assert.notNull(pubJwk.toKey(), "PublicJwk key instance cannot be null.");
        this.context.setPublicKey(publicKey);
        this.keyPair = new KeyPair(publicKey, toKey());
    }

    @Override
    public M toPublicJwk() {
        return this.publicJwk;
    }

    @Override
    public KeyPair toKeyPair() {
        return this.keyPair;
    }
}

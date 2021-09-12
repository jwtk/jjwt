package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PublicJwk;

import java.security.PublicKey;

abstract class AbstractPublicJwk<K extends PublicKey> extends AbstractAsymmetricJwk<K> implements PublicJwk<K> {
    AbstractPublicJwk(JwkContext<K> ctx) {
        super(ctx);
    }
}

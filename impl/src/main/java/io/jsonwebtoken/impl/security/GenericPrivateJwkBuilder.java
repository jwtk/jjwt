package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PrivateJwkBuilder;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface GenericPrivateJwkBuilder<A extends PublicKey, B extends PrivateKey>
        extends PrivateJwkBuilder<B, A, PublicJwk<A>, PrivateJwk<B, A, PublicJwk<A>>, GenericPrivateJwkBuilder<A, B>> {
}

package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface OctetPrivateJwkBuilder<A extends PublicKey, B extends PrivateKey> extends
        PrivateJwkBuilder<B, A, OctetPublicJwk<A>, OctetPrivateJwk<A, B>, OctetPrivateJwkBuilder<A, B>> {
}

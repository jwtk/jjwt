package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface OctetPublicJwkBuilder<A extends PublicKey, B extends PrivateKey>
        extends PublicJwkBuilder<A, B, OctetPublicJwk<A>, OctetPrivateJwk<A, B>, OctetPrivateJwkBuilder<A, B>, OctetPublicJwkBuilder<A, B>> {
}

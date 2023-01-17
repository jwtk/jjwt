package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface OctetPrivateJwk<A extends PublicKey, B extends PrivateKey> extends PrivateJwk<B, A, OctetPublicJwk<A>> {
}

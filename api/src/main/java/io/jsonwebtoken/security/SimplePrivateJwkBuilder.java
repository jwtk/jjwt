package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SimplePrivateJwkBuilder extends PrivateJwkBuilder<PrivateKey, PublicKey,
        PublicJwk<PublicKey>, PrivateJwk<PrivateKey, PublicKey, PublicJwk<PublicKey>>,
        SimplePrivateJwkBuilder> {
}

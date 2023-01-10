package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SimplePublicJwkBuilder extends PublicJwkBuilder<PublicKey, PrivateKey,
        PublicJwk<PublicKey>, PrivateJwk<PrivateKey, PublicKey, PublicJwk<PublicKey>>,
        SimplePrivateJwkBuilder, SimplePublicJwkBuilder>   {
}

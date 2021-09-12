package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

class DefaultEcPrivateJwk extends AbstractPrivateJwk<ECPrivateKey, ECPublicKey, EcPublicJwk> implements EcPrivateJwk {

    static final String D = "d";
    static final Set<String> PRIVATE_NAMES = Collections.setOf(D);

    DefaultEcPrivateJwk(JwkContext<ECPrivateKey> ctx, EcPublicJwk pubJwk) {
        super(ctx, pubJwk);
    }
}

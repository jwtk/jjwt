package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.RsaPublicJwk;

import java.security.interfaces.RSAPublicKey;

class DefaultRsaPublicJwk extends AbstractPublicJwk<RSAPublicKey> implements RsaPublicJwk {

    static final String TYPE_VALUE = "RSA";
    static final String MODULUS = "n";
    static final String PUBLIC_EXPONENT = "e";

    DefaultRsaPublicJwk(JwkContext<RSAPublicKey> ctx) {
        super(ctx);
    }
}

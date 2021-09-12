package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.EcPublicJwk;

import java.security.interfaces.ECPublicKey;

class DefaultEcPublicJwk extends AbstractPublicJwk<ECPublicKey> implements EcPublicJwk {

    static final String TYPE_VALUE = "EC";
    static final String CURVE_ID = "crv";
    static final String X = "x";
    static final String Y = "y";

    DefaultEcPublicJwk(JwkContext<ECPublicKey> ctx) {
        super(ctx);
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

class DefaultEcPublicJwk extends AbstractPublicJwk<ECPublicKey> implements EcPublicJwk {

    static final String TYPE_VALUE = "EC";
    static final Field<String> CRV = Fields.string("crv", "Curve");
    static final Field<BigInteger> X = Fields.bigInt("x", "X Coordinate").build();
    static final Field<BigInteger> Y = Fields.bigInt("y", "Y Coordinate").build();
    static final Set<Field<?>> FIELDS = Collections.immutable(Collections.concat(AbstractAsymmetricJwk.FIELDS, CRV, X, Y));

    DefaultEcPublicJwk(JwkContext<ECPublicKey> ctx) {
        super(ctx);
    }
}

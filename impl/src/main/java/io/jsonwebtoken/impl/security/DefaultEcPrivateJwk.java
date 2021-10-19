package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

class DefaultEcPrivateJwk extends AbstractPrivateJwk<ECPrivateKey, ECPublicKey, EcPublicJwk> implements EcPrivateJwk {

    static final Field<BigInteger> D = Fields.secretBigInt("d", "ECC Private Key");
    static final Set<Field<?>> FIELDS = Collections.immutable(Collections.concat(DefaultEcPublicJwk.FIELDS, D));
    static final Set<String> PRIVATE_NAMES = Collections.setOf(D.getId());

    DefaultEcPrivateJwk(JwkContext<ECPrivateKey> ctx, EcPublicJwk pubJwk) {
        super(ctx, pubJwk);
    }
}

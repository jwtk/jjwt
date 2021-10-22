package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

class DefaultRsaPublicJwk extends AbstractPublicJwk<RSAPublicKey> implements RsaPublicJwk {

    static final String TYPE_VALUE = "RSA";
    static final Field<BigInteger> MODULUS = Fields.bigInt("n", "Modulus").build();
    static final Field<BigInteger> PUBLIC_EXPONENT = Fields.bigInt("e", "Public Exponent").build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractAsymmetricJwk.FIELDS, MODULUS, PUBLIC_EXPONENT);

    DefaultRsaPublicJwk(JwkContext<RSAPublicKey> ctx) {
        super(ctx);
    }
}

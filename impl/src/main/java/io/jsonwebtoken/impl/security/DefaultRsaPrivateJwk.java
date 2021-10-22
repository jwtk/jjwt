package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAOtherPrimeInfo;
import java.util.Set;

class DefaultRsaPrivateJwk extends AbstractPrivateJwk<RSAPrivateKey, RSAPublicKey, RsaPublicJwk> implements RsaPrivateJwk {

    static final Field<BigInteger> PRIVATE_EXPONENT = Fields.secretBigInt("d", "Private Exponent");
    static final Field<BigInteger> FIRST_PRIME = Fields.secretBigInt("p", "First Prime Factor");
    static final Field<BigInteger> SECOND_PRIME = Fields.secretBigInt("q", "Second Prime Factor");
    static final Field<BigInteger> FIRST_CRT_EXPONENT = Fields.secretBigInt("dp", "First Factor CRT Exponent");
    static final Field<BigInteger> SECOND_CRT_EXPONENT = Fields.secretBigInt("dq", "Second Factor CRT Exponent");
    static final Field<BigInteger> FIRST_CRT_COEFFICIENT = Fields.secretBigInt("qi", "First CRT Coefficient");
    static final Field<RSAOtherPrimeInfo> OTHER_PRIMES_INFO = Fields.builder(RSAOtherPrimeInfo.class).setSecret(true)
        .setId("oth").setName("Other Primes Info")
        .setConverter(new RsaPrivateJwkFactory.RSAOtherPrimeInfoConverter())
        .build();

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultRsaPublicJwk.FIELDS,
        PRIVATE_EXPONENT, FIRST_PRIME, SECOND_PRIME, FIRST_CRT_EXPONENT,
        SECOND_CRT_EXPONENT, FIRST_CRT_COEFFICIENT, OTHER_PRIMES_INFO
    );

    DefaultRsaPrivateJwk(JwkContext<RSAPrivateKey> ctx, RsaPublicJwk pubJwk) {
        super(ctx, pubJwk);
    }
}

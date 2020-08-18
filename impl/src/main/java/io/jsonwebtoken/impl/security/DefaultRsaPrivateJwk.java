package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashSet;
import java.util.Set;

class DefaultRsaPrivateJwk extends AbstractPrivateJwk<RSAPrivateKey, RSAPublicKey, RsaPublicJwk> implements RsaPrivateJwk {

    static String PRIVATE_EXPONENT = "d";
    static String FIRST_PRIME = "p";
    static String SECOND_PRIME = "q";
    static String FIRST_CRT_EXPONENT = "dp";
    static String SECOND_CRT_EXPONENT = "dq";
    static String FIRST_CRT_COEFFICIENT = "qi";
    static String OTHER_PRIMES_INFO = "oth";
    static String PRIME_FACTOR = "r";
    static String FACTOR_CRT_EXPONENT = "d";
    static String FACTOR_CRT_COEFFICIENT = "t";

    static final Set<String> PRIVATE_NAMES = Collections.setOf(
        PRIVATE_EXPONENT, FIRST_PRIME, SECOND_PRIME,
        FIRST_CRT_EXPONENT, SECOND_CRT_EXPONENT,
        FIRST_CRT_COEFFICIENT, OTHER_PRIMES_INFO);

    static final Set<String> OPTIONAL_PRIVATE_NAMES;

    static {
        OPTIONAL_PRIVATE_NAMES = new LinkedHashSet<>(PRIVATE_NAMES);
        OPTIONAL_PRIVATE_NAMES.remove(PRIVATE_EXPONENT);
    }

    DefaultRsaPrivateJwk(JwkContext<RSAPrivateKey> ctx, RsaPublicJwk pubJwk) {
        super(ctx, pubJwk);
    }
}

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.MalformedKeyException;

import java.math.BigInteger;
import java.security.spec.RSAOtherPrimeInfo;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

class RSAOtherPrimeInfoConverter implements Converter<RSAOtherPrimeInfo, Object> {

    static final RSAOtherPrimeInfoConverter INSTANCE = new RSAOtherPrimeInfoConverter();

    static final Field<BigInteger> PRIME_FACTOR = Fields.secretBigInt("r", "Prime Factor");
    static final Field<BigInteger> FACTOR_CRT_EXPONENT = Fields.secretBigInt("d", "Factor CRT Exponent");
    static final Field<BigInteger> FACTOR_CRT_COEFFICIENT = Fields.secretBigInt("t", "Factor CRT Coefficient");
    static final Set<Field<?>> FIELDS = Collections.<Field<?>>setOf(PRIME_FACTOR, FACTOR_CRT_EXPONENT, FACTOR_CRT_COEFFICIENT);

    @Override
    public Object applyTo(RSAOtherPrimeInfo info) {
        Map<String, String> m = new LinkedHashMap<>(3);
        m.put(PRIME_FACTOR.getId(), (String)PRIME_FACTOR.applyTo(info.getPrime()));
        m.put(FACTOR_CRT_EXPONENT.getId(), (String)FACTOR_CRT_EXPONENT.applyTo(info.getExponent()));
        m.put(FACTOR_CRT_COEFFICIENT.getId(), (String)FACTOR_CRT_COEFFICIENT.applyTo(info.getCrtCoefficient()));
        return m;
    }

    @Override
    public RSAOtherPrimeInfo applyFrom(Object o) {
        if (o == null) {
            throw new MalformedKeyException("RSA JWK 'oth' (Other Prime Info) element cannot be null.");
        }
        if (!(o instanceof Map)) {
            String msg = "RSA JWK 'oth' (Other Prime Info) must contain map elements of name/value pairs. " +
                    "Element type found: " + o.getClass().getName();
            throw new MalformedKeyException(msg);
        }
        Map<?, ?> m = (Map<?, ?>) o;
        if (Collections.isEmpty(m)) {
            throw new MalformedKeyException("RSA JWK 'oth' (Other Prime Info) element map cannot be empty.");
        }

        // Need to add the values to a Context instance to satisfy the API contract of the getRequired* methods
        // called below.  It's less than ideal, but it works:
        JwkContext<?> ctx = new DefaultJwkContext<>(FIELDS);
        for (Map.Entry<?, ?> entry : m.entrySet()) {
            String name = String.valueOf(entry.getKey());
            ctx.put(name, entry.getValue());
        }

        final ValueGetter getter = new DefaultValueGetter(ctx);
        BigInteger prime = getter.getRequiredBigInt(PRIME_FACTOR.getId(), true);
        BigInteger primeExponent = getter.getRequiredBigInt(FACTOR_CRT_EXPONENT.getId(), true);
        BigInteger crtCoefficient = getter.getRequiredBigInt(FACTOR_CRT_COEFFICIENT.getId(), true);

        return new RSAOtherPrimeInfo(prime, primeExponent, crtCoefficient);
    }
}

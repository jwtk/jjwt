package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAOtherPrimeInfo;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class RsaPrivateJwkFactory extends AbstractFamilyJwkFactory<RSAPrivateKey, RsaPrivateJwk> {

    static final Converter<List<RSAOtherPrimeInfo>, Object> RSA_OTHER_PRIMES_CONVERTER =
        Converters.forList(new RSAOtherPrimeInfoConverter());

    private static final String PUBKEY_ERR_MSG = "JwkContext publicKey must be an " + RSAPublicKey.class.getName() + " instance.";

    RsaPrivateJwkFactory() {
        super(DefaultRsaPublicJwk.TYPE_VALUE, RSAPrivateKey.class);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultRsaPrivateJwk.PRIVATE_EXPONENT.getId());
    }

    private static BigInteger getPublicExponent(RSAPrivateKey key) {
        if (key instanceof RSAPrivateCrtKey) {
            return ((RSAPrivateCrtKey) key).getPublicExponent();
        } else if (key instanceof RSAMultiPrimePrivateCrtKey) {
            return ((RSAMultiPrimePrivateCrtKey) key).getPublicExponent();
        }

        String msg = "Unable to derive RSAPublicKey from RSAPrivateKey implementation [" +
            key.getClass().getName() + "].  Supported keys implement the " +
            RSAPrivateCrtKey.class.getName() + " or " + RSAMultiPrimePrivateCrtKey.class.getName() +
            " interfaces.  If the specified RSAPrivateKey cannot be one of these two, you must explicitly " +
            "provide an RSAPublicKey in addition to the RSAPrivateKey, as the " +
            "[JWA RFC, Section 6.3.2](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2) " +
            "requires public values to be present in private RSA JWKs.";
        throw new UnsupportedKeyException(msg);
    }

    private RSAPublicKey derivePublic(final JwkContext<RSAPrivateKey> ctx) {
        RSAPrivateKey key = ctx.getKey();
        BigInteger modulus = key.getModulus();
        BigInteger publicExponent = getPublicExponent(key);
        final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        return generateKey(ctx, RSAPublicKey.class, new CheckedFunction<KeyFactory, RSAPublicKey>() {
            @Override
            public RSAPublicKey apply(KeyFactory kf) {
                try {
                    return (RSAPublicKey) kf.generatePublic(spec);
                } catch (Exception e) {
                    String msg = "Unable to derive RSAPublicKey from RSAPrivateKey {" + ctx + "}.";
                    throw new UnsupportedKeyException(msg);
                }
            }
        });
    }

    @Override
    protected RsaPrivateJwk createJwkFromKey(JwkContext<RSAPrivateKey> ctx) {

        RSAPrivateKey key = ctx.getKey();
        RSAPublicKey rsaPublicKey;

        PublicKey publicKey = ctx.getPublicKey();
        if (publicKey != null) {
            rsaPublicKey = Assert.isInstanceOf(RSAPublicKey.class, publicKey, PUBKEY_ERR_MSG);
        } else {
            rsaPublicKey = derivePublic(ctx);
        }

        // The [JWA Spec](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1)
        // requires public values to be present in private JWKs, so add them:
        JwkContext<RSAPublicKey> pubCtx = new DefaultJwkContext<>(DefaultRsaPrivateJwk.PRIVATE_NAMES, ctx, rsaPublicKey);
        RsaPublicJwk pubJwk = RsaPublicJwkFactory.DEFAULT_INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk); // add public values to private key context

        ctx.put(DefaultRsaPrivateJwk.PRIVATE_EXPONENT.getId(), encode(key.getPrivateExponent()));

        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey ckey = (RSAPrivateCrtKey) key;
            //noinspection DuplicatedCode
            ctx.put(DefaultRsaPrivateJwk.FIRST_PRIME.getId(), encode(ckey.getPrimeP()));
            ctx.put(DefaultRsaPrivateJwk.SECOND_PRIME.getId(), encode(ckey.getPrimeQ()));
            ctx.put(DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT.getId(), encode(ckey.getPrimeExponentP()));
            ctx.put(DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT.getId(), encode(ckey.getPrimeExponentQ()));
            ctx.put(DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT.getId(), encode(ckey.getCrtCoefficient()));
        } else if (key instanceof RSAMultiPrimePrivateCrtKey) {
            RSAMultiPrimePrivateCrtKey ckey = (RSAMultiPrimePrivateCrtKey) key;
            //noinspection DuplicatedCode
            ctx.put(DefaultRsaPrivateJwk.FIRST_PRIME.getId(), encode(ckey.getPrimeP()));
            ctx.put(DefaultRsaPrivateJwk.SECOND_PRIME.getId(), encode(ckey.getPrimeQ()));
            ctx.put(DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT.getId(), encode(ckey.getPrimeExponentP()));
            ctx.put(DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT.getId(), encode(ckey.getPrimeExponentQ()));
            ctx.put(DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT.getId(), encode(ckey.getCrtCoefficient()));
            List<RSAOtherPrimeInfo> infos = Arrays.asList(ckey.getOtherPrimeInfo());
            if (!Collections.isEmpty(infos)) {
                Object val = RSA_OTHER_PRIMES_CONVERTER.applyTo(infos);
                ctx.put(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId(), val);
            }
        }

        return new DefaultRsaPrivateJwk(ctx, pubJwk);
    }

    @Override
    protected RsaPrivateJwk createJwkFromValues(JwkContext<RSAPrivateKey> ctx) {

        final ValueGetter getter = new DefaultValueGetter(ctx);
        final BigInteger privateExponent = getter.getRequiredBigInt(DefaultRsaPrivateJwk.PRIVATE_EXPONENT.getId(), true);

        //The [JWA Spec, Section 6.3.2](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2) requires
        //RSA Private Keys to also encode the public key values, so we assert that we can acquire it successfully:
        JwkContext<RSAPublicKey> pubCtx = new DefaultJwkContext<>(DefaultRsaPrivateJwk.PRIVATE_NAMES, ctx);
        RsaPublicJwk pubJwk = RsaPublicJwkFactory.DEFAULT_INSTANCE.createJwkFromValues(pubCtx);
        RSAPublicKey pubKey = pubJwk.toKey();
        final BigInteger modulus = pubKey.getModulus();
        final BigInteger publicExponent = pubKey.getPublicExponent();

        // JWA Section 6.3.2 also indicates that if any of the optional private names are present, then *all* of those
        // optional values must be present (except 'oth', which is handled separately next).  Quote:
        //
        //     If the producer includes any of the other private key parameters, then all of the others MUST
        //     be present, with the exception of "oth", which MUST only be present when more than two prime
        //     factors were used
        //
        boolean containsOptional = false;
        for (String optionalPrivateName : DefaultRsaPrivateJwk.OPTIONAL_PRIVATE_NAMES) {
            if (ctx.containsKey(optionalPrivateName)) {
                containsOptional = true;
                break;
            }
        }

        KeySpec spec;

        if (containsOptional) { //if any one optional field exists, they are all required per JWA Section 6.3.2:
            BigInteger firstPrime = getter.getRequiredBigInt(DefaultRsaPrivateJwk.FIRST_PRIME.getId(), true);
            BigInteger secondPrime = getter.getRequiredBigInt(DefaultRsaPrivateJwk.SECOND_PRIME.getId(), true);
            BigInteger firstCrtExponent = getter.getRequiredBigInt(DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT.getId(), true);
            BigInteger secondCrtExponent = getter.getRequiredBigInt(DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT.getId(), true);
            BigInteger firstCrtCoefficient = getter.getRequiredBigInt(DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT.getId(), true);

            // Other Primes Info is actually optional even if the above ones are required:
            if (ctx.containsKey(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId())) {

                Object value = ctx.get(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId());
                List<RSAOtherPrimeInfo> otherPrimes = RSA_OTHER_PRIMES_CONVERTER.applyFrom(value);

                RSAOtherPrimeInfo[] arr = new RSAOtherPrimeInfo[otherPrimes.size()];
                otherPrimes.toArray(arr);

                spec = new RSAMultiPrimePrivateCrtKeySpec(modulus, publicExponent, privateExponent, firstPrime,
                    secondPrime, firstCrtExponent, secondCrtExponent, firstCrtCoefficient, arr);
            } else {
                spec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, firstPrime, secondPrime,
                    firstCrtExponent, secondCrtExponent, firstCrtCoefficient);
            }
        } else {
            spec = new RSAPrivateKeySpec(modulus, privateExponent);
        }

        final KeySpec keySpec = spec;
        RSAPrivateKey key = generateKey(ctx, new CheckedFunction<KeyFactory, RSAPrivateKey>() {
            @Override
            public RSAPrivateKey apply(KeyFactory kf) throws Exception {
                return (RSAPrivateKey) kf.generatePrivate(keySpec);
            }
        });
        ctx.setKey(key);

        return new DefaultRsaPrivateJwk(ctx, pubJwk);
    }

    static class RSAOtherPrimeInfoConverter implements Converter<RSAOtherPrimeInfo, Object> {

        static final Field<BigInteger> PRIME_FACTOR = Fields.secretBigInt("r", "Prime Factor");
        static final Field<BigInteger> FACTOR_CRT_EXPONENT = Fields.secretBigInt("d", "Factor CRT Exponent");
        static final Field<BigInteger> FACTOR_CRT_COEFFICIENT = Fields.secretBigInt("t", "Factor CRT Coefficient");

        @Override
        public Object applyTo(RSAOtherPrimeInfo info) {
            Map<String, String> m = new LinkedHashMap<>(3);
            m.put(PRIME_FACTOR.getId(), encode(info.getPrime()));
            m.put(FACTOR_CRT_EXPONENT.getId(), encode(info.getExponent()));
            m.put(FACTOR_CRT_COEFFICIENT.getId(), encode(info.getCrtCoefficient()));
            return m;
        }

        @Override
        public RSAOtherPrimeInfo applyFrom(Object o) {
            if (o == null) {
                throw new MalformedKeyException("RSA JWK 'oth' Other Prime Info element cannot be null.");
            }
            if (!(o instanceof Map)) {
                String msg = "RSA JWK 'oth' Other Prime Info list must contain map elements of name/value pairs. " +
                    "Element type found: " + o.getClass().getName();
                throw new MalformedKeyException(msg);
            }
            Map<?, ?> m = (Map<?, ?>) o;
            if (Collections.isEmpty(m)) {
                throw new MalformedKeyException("RSA JWK 'oth' Other Prime Info element map cannot be empty.");
            }

            // Need to add the values to a Context instance to satisfy the API contract of the getRequired* methods
            // called below.  It's less than ideal, but it works:
            JwkContext<?> ctx = new DefaultJwkContext<>(DefaultRsaPrivateJwk.PRIVATE_NAMES);
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
}

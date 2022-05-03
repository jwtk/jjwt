package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
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
import java.util.List;
import java.util.Set;

class RsaPrivateJwkFactory extends AbstractFamilyJwkFactory<RSAPrivateKey, RsaPrivateJwk> {

    //All RSA Private fields _except_ for PRIVATE_EXPONENT.  That is always required:
    private static final Set<Field<BigInteger>> OPTIONAL_PRIVATE_FIELDS = Collections.setOf(
        DefaultRsaPrivateJwk.FIRST_PRIME, DefaultRsaPrivateJwk.SECOND_PRIME,
        DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT, DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT,
        DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT
    );

    static final Converter<List<RSAOtherPrimeInfo>, Object> RSA_OTHER_PRIMES_CONVERTER =
        Converters.forList(RSAOtherPrimeInfoConverter.INSTANCE);

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
                    String msg = "Unable to derive RSAPublicKey from RSAPrivateKey " + ctx +
                            ". Cause: " + e.getMessage();
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
        JwkContext<RSAPublicKey> pubCtx = new DefaultJwkContext<>(DefaultRsaPublicJwk.FIELDS, ctx, rsaPublicKey);
        RsaPublicJwk pubJwk = RsaPublicJwkFactory.DEFAULT_INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk); // add public values to private key context

        put(ctx, DefaultRsaPrivateJwk.PRIVATE_EXPONENT, key.getPrivateExponent());

        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey ckey = (RSAPrivateCrtKey) key;
            //noinspection DuplicatedCode
            put(ctx, DefaultRsaPrivateJwk.FIRST_PRIME, ckey.getPrimeP());
            put(ctx, DefaultRsaPrivateJwk.SECOND_PRIME, ckey.getPrimeQ());
            put(ctx, DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT, ckey.getPrimeExponentP());
            put(ctx, DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT, ckey.getPrimeExponentQ());
            put(ctx, DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT, ckey.getCrtCoefficient());
        } else if (key instanceof RSAMultiPrimePrivateCrtKey) {
            RSAMultiPrimePrivateCrtKey ckey = (RSAMultiPrimePrivateCrtKey) key;
            //noinspection DuplicatedCode
            put(ctx, DefaultRsaPrivateJwk.FIRST_PRIME, ckey.getPrimeP());
            put(ctx, DefaultRsaPrivateJwk.SECOND_PRIME, ckey.getPrimeQ());
            put(ctx, DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT, ckey.getPrimeExponentP());
            put(ctx, DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT, ckey.getPrimeExponentQ());
            put(ctx, DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT, ckey.getCrtCoefficient());
            List<RSAOtherPrimeInfo> infos = Arrays.asList(ckey.getOtherPrimeInfo());
            if (!Collections.isEmpty(infos)) {
                put(ctx,DefaultRsaPrivateJwk.OTHER_PRIMES_INFO, infos);
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
        JwkContext<RSAPublicKey> pubCtx = new DefaultJwkContext<>(DefaultRsaPublicJwk.FIELDS, ctx);
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
        for (Field<?> field : OPTIONAL_PRIVATE_FIELDS) {
            if (ctx.containsKey(field.getId())) {
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

                RSAOtherPrimeInfo[] arr = new RSAOtherPrimeInfo[Collections.size(otherPrimes)];
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

        RSAPrivateKey key = generateFromSpec(ctx, spec);
        ctx.setKey(key);

        return new DefaultRsaPrivateJwk(ctx, pubJwk);
    }

    protected RSAPrivateKey generateFromSpec(JwkContext<RSAPrivateKey> ctx, final KeySpec keySpec) {
        return generateKey(ctx, new CheckedFunction<KeyFactory, RSAPrivateKey>() {
            @Override
            public RSAPrivateKey apply(KeyFactory kf) throws Exception {
                return (RSAPrivateKey) kf.generatePrivate(keySpec);
            }
        });
    }
}

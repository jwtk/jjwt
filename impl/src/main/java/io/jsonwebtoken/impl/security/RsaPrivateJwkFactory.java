/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
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

    //All RSA Private params _except_ for PRIVATE_EXPONENT.  That is always required:
    private static final Set<Parameter<BigInteger>> OPTIONAL_PRIVATE_PARAMS = Collections.setOf(
            DefaultRsaPrivateJwk.FIRST_PRIME, DefaultRsaPrivateJwk.SECOND_PRIME,
            DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT, DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT,
            DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT
    );

    private static final String PUBKEY_ERR_MSG = "JwkContext publicKey must be an " + RSAPublicKey.class.getName() + " instance.";
    private static final String PUB_EXPONENT_EX_MSG =
            "Unable to derive RSAPublicKey from RSAPrivateKey [%s]. Supported keys implement the " +
                    RSAPrivateCrtKey.class.getName() + " or " + RSAMultiPrimePrivateCrtKey.class.getName() +
                    " interfaces.  If the specified RSAPrivateKey cannot be one of these two, you must explicitly " +
                    "provide an RSAPublicKey in addition to the RSAPrivateKey, as the " +
                    "[JWA RFC, Section 6.3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2) " +
                    "requires public values to be present in private RSA JWKs.";

    RsaPrivateJwkFactory() {
        super(DefaultRsaPublicJwk.TYPE_VALUE, RSAPrivateKey.class, DefaultRsaPrivateJwk.PARAMS);
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

        String msg = String.format(PUB_EXPONENT_EX_MSG, KeysBridge.toString(key));
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
                    String msg = "Unable to derive RSAPublicKey from RSAPrivateKey " + ctx + ". Cause: " + e.getMessage();
                    throw new InvalidKeyException(msg);
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

        // The [JWA Spec](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1)
        // requires public values to be present in private JWKs, so add them:

        // If a JWK fingerprint has been requested to be the JWK id, ensure we copy over the one computed for the
        // public key per https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        boolean copyId = !Strings.hasText(ctx.getId()) && ctx.getIdThumbprintAlgorithm() != null;

        JwkContext<RSAPublicKey> pubCtx = RsaPublicJwkFactory.INSTANCE.newContext(ctx, rsaPublicKey);
        RsaPublicJwk pubJwk = RsaPublicJwkFactory.INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk); // add public values to private key context
        if (copyId) {
            ctx.setId(pubJwk.getId());
        }

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
                put(ctx, DefaultRsaPrivateJwk.OTHER_PRIMES_INFO, infos);
            }
        }

        return new DefaultRsaPrivateJwk(ctx, pubJwk);
    }

    @Override
    protected RsaPrivateJwk createJwkFromValues(JwkContext<RSAPrivateKey> ctx) {

        final ParameterReadable reader = new RequiredParameterReader(ctx);

        final BigInteger privateExponent = reader.get(DefaultRsaPrivateJwk.PRIVATE_EXPONENT);

        //The [JWA Spec, Section 6.3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2) requires
        //RSA Private Keys to also encode the public key values, so we assert that we can acquire it successfully:
        JwkContext<RSAPublicKey> pubCtx = new DefaultJwkContext<>(DefaultRsaPublicJwk.PARAMS, ctx);
        RsaPublicJwk pubJwk = RsaPublicJwkFactory.INSTANCE.createJwkFromValues(pubCtx);
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
        for (Parameter<?> param : OPTIONAL_PRIVATE_PARAMS) {
            if (ctx.containsKey(param.getId())) {
                containsOptional = true;
                break;
            }
        }

        KeySpec spec;

        if (containsOptional) { //if any one optional parameter exists, they are all required per JWA Section 6.3.2:
            BigInteger firstPrime = reader.get(DefaultRsaPrivateJwk.FIRST_PRIME);
            BigInteger secondPrime = reader.get(DefaultRsaPrivateJwk.SECOND_PRIME);
            BigInteger firstCrtExponent = reader.get(DefaultRsaPrivateJwk.FIRST_CRT_EXPONENT);
            BigInteger secondCrtExponent = reader.get(DefaultRsaPrivateJwk.SECOND_CRT_EXPONENT);
            BigInteger firstCrtCoefficient = reader.get(DefaultRsaPrivateJwk.FIRST_CRT_COEFFICIENT);

            // Other Primes Info is actually optional even if the above ones are required:
            if (ctx.containsKey(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId())) {
                List<RSAOtherPrimeInfo> otherPrimes = reader.get(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO);
                RSAOtherPrimeInfo[] arr = new RSAOtherPrimeInfo[Collections.size(otherPrimes)];
                arr = otherPrimes.toArray(arr);
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

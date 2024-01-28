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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @since 0.12.0
 */
class SecretJwkFactory extends AbstractFamilyJwkFactory<SecretKey, SecretJwk> {

    SecretJwkFactory() {
        super(DefaultSecretJwk.TYPE_VALUE, SecretKey.class, DefaultSecretJwk.PARAMS);
    }

    @Override
    protected SecretJwk createJwkFromKey(JwkContext<SecretKey> ctx) {
        SecretKey key = Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
        String k;
        byte[] encoded = null;
        try {
            encoded = KeysBridge.getEncoded(key);
            k = Encoders.BASE64URL.encode(encoded);
            Assert.hasText(k, "k value cannot be null or empty.");
        } catch (Throwable t) {
            String msg = "Unable to encode SecretKey to JWK: " + t.getMessage();
            throw new InvalidKeyException(msg, t);
        } finally {
            Bytes.clear(encoded);
        }

        MacAlgorithm mac = DefaultMacAlgorithm.findByKey(key);
        if (mac != null) {
            ctx.put(AbstractJwk.ALG.getId(), mac.getId());
        }

        ctx.put(DefaultSecretJwk.K.getId(), k);

        return createJwkFromValues(ctx);
    }

    private static void assertKeyBitLength(byte[] bytes, MacAlgorithm alg) {
        long bitLen = Bytes.bitLength(bytes);
        long requiredBitLen = alg.getKeyBitLength();
        if (bitLen < requiredBitLen) {
            // Implementors note:  Don't print out any information about the `bytes` value itself - size,
            // content, etc., as it is considered secret material:
            String msg = "Secret JWK " + AbstractJwk.ALG + " value is '" + alg.getId() +
                    "', but the " + DefaultSecretJwk.K + " length is smaller than the " + alg.getId() +
                    " minimum length of " + Bytes.bitsMsg(requiredBitLen) +
                    " required by " +
                    "[JWA RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2), " +
                    "2nd paragraph: 'A key of the same size as the hash output or larger MUST be used with this " +
                    "algorithm.'";
            throw new WeakKeyException(msg);
        }
    }

    private static void assertSymmetric(Identifiable alg) {
        if (alg instanceof MacAlgorithm || alg instanceof SecretKeyAlgorithm || alg instanceof AeadAlgorithm)
            return; // valid
        String msg = "Invalid Secret JWK " + AbstractJwk.ALG + " value '" + alg.getId() + "'. Secret JWKs " +
                "may only be used with symmetric (secret) key algorithms.";
        throw new MalformedKeyException(msg);
    }

    @Override
    protected SecretJwk createJwkFromValues(JwkContext<SecretKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        final byte[] bytes = reader.get(DefaultSecretJwk.K);
        SecretKey key;

        String algId = ctx.getAlgorithm();
        if (!Strings.hasText(algId)) { // optional per https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4

            // Here we try to infer the best type of key to create based on siguse and/or key length.
            //
            // AES requires 128, 192, or 256 bits, so anything larger than 256 cannot be AES, so we'll need to assume
            // HMAC.
            //
            // Also, 256 bits works for either HMAC or AES, so we just have to choose one as there is no other
            // RFC-based criteria for determining.  Historically, we've chosen AES due to the larger number of
            // KeyAlgorithm and AeadAlgorithm use cases, so that's our default.
            int kBitLen = (int) Bytes.bitLength(bytes);

            if (ctx.isSigUse() || kBitLen > Jwts.SIG.HS256.getKeyBitLength()) {
                // The only JWA SecretKey signature algorithms are HS256, HS384, HS512, so choose based on bit length:
                key = Keys.hmacShaKeyFor(bytes);
            } else {
                key = AesAlgorithm.keyFor(bytes);
            }
            ctx.setKey(key);
            return new DefaultSecretJwk(ctx);
        }

        //otherwise 'alg' was specified, ensure it's valid for secret key use:
        Identifiable alg = Jwts.SIG.get().get(algId);
        if (alg == null) alg = Jwts.KEY.get().get(algId);
        if (alg == null) alg = Jwts.ENC.get().get(algId);
        if (alg != null) assertSymmetric(alg); // if we found a standard alg, it must be a symmetric key algorithm

        if (alg instanceof MacAlgorithm) {
            assertKeyBitLength(bytes, ((MacAlgorithm) alg));
            String jcaName = ((CryptoAlgorithm) alg).getJcaName();
            Assert.hasText(jcaName, "Algorithm jcaName cannot be null or empty.");
            key = new SecretKeySpec(bytes, jcaName);
        } else {
            // all other remaining JWA-standard symmetric algs use AES:
            key = AesAlgorithm.keyFor(bytes);
        }
        ctx.setKey(key);
        return new DefaultSecretJwk(ctx);
    }
}

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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
class SecretJwkFactory extends AbstractFamilyJwkFactory<SecretKey, SecretJwk> {

    SecretJwkFactory() {
        super(DefaultSecretJwk.TYPE_VALUE, SecretKey.class, DefaultSecretJwk.PARAMS);
    }

    @Override
    protected SecretJwk createJwkFromKey(JwkContext<SecretKey> ctx) {
        SecretKey key = Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
        String k;
        try {
            byte[] encoded = KeysBridge.getEncoded(key);
            k = Encoders.BASE64URL.encode(encoded);
            Assert.hasText(k, "k value cannot be null or empty.");
        } catch (Throwable t) {
            String msg = "Unable to encode SecretKey to JWK: " + t.getMessage();
            throw new InvalidKeyException(msg, t);
        }

        ctx.put(DefaultSecretJwk.K.getId(), k);

        return new DefaultSecretJwk(ctx);
    }

    private static void assertKeyBitLength(byte[] bytes, MacAlgorithm alg) {
        long bitLen = Bytes.bitLength(bytes);
        long requiredBitLen = alg.getKeyBitLength();
        if (bitLen != requiredBitLen) {
            // Implementors note:  Don't print out any information about the `bytes` value itself - size,
            // content, etc., as it is considered secret material:
            String msg = "Secret JWK " + AbstractJwk.ALG + " value is '" + alg.getId() +
                    "', but the " + DefaultSecretJwk.K + " length does not equal the '" + alg.getId() +
                    "' length requirement of " + Bytes.bitsMsg(requiredBitLen) +
                    ". This discrepancy could be the result of an algorithm " +
                    "substitution attack or simply an erroneously constructed JWK. In either case, it is likely " +
                    "to result in unexpected or undesired security consequences.";
            throw new MalformedKeyException(msg);
        }
    }

    @Override
    protected SecretJwk createJwkFromValues(JwkContext<SecretKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        byte[] bytes = reader.get(DefaultSecretJwk.K);
        String jcaName = null;

        String id = ctx.getAlgorithm();
        if (Strings.hasText(id)) {
            SecureDigestAlgorithm<?, ?> alg = Jwts.SIG.get().get(id);
            if (alg instanceof MacAlgorithm) {
                jcaName = ((CryptoAlgorithm) alg).getJcaName(); // valid for all JJWT alg implementations
                Assert.hasText(jcaName, "Algorithm jcaName cannot be null or empty.");
                assertKeyBitLength(bytes, (MacAlgorithm) alg);
            }
        }
        if (!Strings.hasText(jcaName)) {
            if (ctx.isSigUse()) {
                // The only JWA SecretKey signature algorithms are HS256, HS384, HS512, so choose based on bit length:
                jcaName = "HmacSHA" + Bytes.bitLength(bytes);
            } else { // not an HS* algorithm, and all standard AeadAlgorithms use AES keys:
                jcaName = AesAlgorithm.KEY_ALG_NAME;
            }
        }
        Assert.stateNotNull(jcaName, "jcaName cannot be null (invariant)");
        SecretKey key = new SecretKeySpec(bytes, jcaName);
        ctx.setKey(key);
        return new DefaultSecretJwk(ctx);
    }
}

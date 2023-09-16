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
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.InvalidKeyException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

class EcPrivateJwkFactory extends AbstractEcJwkFactory<ECPrivateKey, EcPrivateJwk> {

    private static final String ECPUBKEY_ERR_MSG = "JwkContext publicKey must be an " + ECPublicKey.class.getName() + " instance.";

    private static final EcPublicJwkFactory PUB_FACTORY = EcPublicJwkFactory.INSTANCE;

    EcPrivateJwkFactory() {
        super(ECPrivateKey.class, DefaultEcPrivateJwk.PARAMS);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultEcPrivateJwk.D.getId());
    }

    // visible for testing
    protected ECPublicKey derivePublic(KeyFactory keyFactory, ECPublicKeySpec spec) throws InvalidKeySpecException {
        return (ECPublicKey) keyFactory.generatePublic(spec);
    }

    protected ECPublicKey derivePublic(final JwkContext<ECPrivateKey> ctx) {
        final ECPrivateKey key = ctx.getKey();
        return generateKey(ctx, ECPublicKey.class, new CheckedFunction<KeyFactory, ECPublicKey>() {
            @Override
            public ECPublicKey apply(KeyFactory kf) {
                try {
                    ECPublicKeySpec spec = ECCurve.publicKeySpec(key);
                    return derivePublic(kf, spec);
                } catch (Exception e) {
                    String msg = "Unable to derive ECPublicKey from ECPrivateKey: " + e.getMessage();
                    throw new InvalidKeyException(msg, e);
                }
            }
        });
    }

    @Override
    protected EcPrivateJwk createJwkFromKey(JwkContext<ECPrivateKey> ctx) {

        ECPrivateKey key = ctx.getKey();
        ECPublicKey ecPublicKey;

        PublicKey publicKey = ctx.getPublicKey();
        if (publicKey != null) {
            ecPublicKey = Assert.isInstanceOf(ECPublicKey.class, publicKey, ECPUBKEY_ERR_MSG);
        } else {
            ecPublicKey = derivePublic(ctx);
        }

        // [JWA spec](https://tools.ietf.org/html/rfc7518#section-6.2.2)
        // requires public values to be present in private JWKs, so add them:

        // If a JWK fingerprint has been requested to be the JWK id, ensure we copy over the one computed for the
        // public key per https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        boolean copyId = !Strings.hasText(ctx.getId()) && ctx.getIdThumbprintAlgorithm() != null;

        JwkContext<ECPublicKey> pubCtx = PUB_FACTORY.newContext(ctx, ecPublicKey);
        EcPublicJwk pubJwk = PUB_FACTORY.createJwk(pubCtx);
        ctx.putAll(pubJwk); // add public values to private key context
        if (copyId) {
            ctx.setId(pubJwk.getId());
        }

        int fieldSize = key.getParams().getCurve().getField().getFieldSize();
        String d = toOctetString(fieldSize, key.getS());
        ctx.put(DefaultEcPrivateJwk.D.getId(), d);

        return new DefaultEcPrivateJwk(ctx, pubJwk);
    }

    @Override
    protected EcPrivateJwk createJwkFromValues(final JwkContext<ECPrivateKey> ctx) {

        ParameterReadable reader = new RequiredParameterReader(ctx);
        String curveId = reader.get(DefaultEcPublicJwk.CRV);
        BigInteger d = reader.get(DefaultEcPrivateJwk.D);

        // We don't actually need the public x,y point coordinates for JVM lookup, but the
        // [JWA spec](https://tools.ietf.org/html/rfc7518#section-6.2.2)
        // requires them to be present and valid for the private key as well, so we assert that here:
        JwkContext<ECPublicKey> pubCtx = new DefaultJwkContext<>(DefaultEcPublicJwk.PARAMS, ctx);
        EcPublicJwk pubJwk = EcPublicJwkFactory.INSTANCE.createJwk(pubCtx);

        ECCurve curve = getCurveByJwaId(curveId);
        final ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(d, curve.toParameterSpec());
        ECPrivateKey key = generateKey(ctx, new CheckedFunction<KeyFactory, ECPrivateKey>() {
            @Override
            public ECPrivateKey apply(KeyFactory kf) throws Exception {
                return (ECPrivateKey) kf.generatePrivate(privateSpec);
            }
        });

        ctx.setKey(key);

        return new DefaultEcPrivateJwk(ctx, pubJwk);
    }
}

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
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.InvalidKeyException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Map;

class EcPublicJwkFactory extends AbstractEcJwkFactory<ECPublicKey, EcPublicJwk> {

    private static final String UNSUPPORTED_CURVE_MSG = "The specified ECKey curve does not match a JWA standard curve id.";

    static final EcPublicJwkFactory INSTANCE = new EcPublicJwkFactory();

    EcPublicJwkFactory() {
        super(ECPublicKey.class, DefaultEcPublicJwk.PARAMS);
    }

    protected static String keyContainsErrorMessage(String curveId) {
        Assert.hasText(curveId, "curveId cannot be null or empty.");
        String fmt = "ECPublicKey's ECPoint does not exist on elliptic curve '%s' " +
                "and may not be used to create '%s' JWKs.";
        return String.format(fmt, curveId, curveId);
    }

    protected static String jwkContainsErrorMessage(String curveId, Map<String, ?> jwk) {
        Assert.hasText(curveId, "curveId cannot be null or empty.");
        String fmt = "EC JWK x,y coordinates do not exist on elliptic curve '%s'. This " +
                "could be due simply to an incorrectly-created JWK or possibly an attempted Invalid Curve Attack " +
                "(see https://safecurves.cr.yp.to/twist.html for more information).";
        return String.format(fmt, curveId, jwk);
    }

    protected static String getJwaIdByCurve(EllipticCurve curve) {
        ECCurve c = ECCurve.findByJcaCurve(curve);
        if (c == null) {
            throw new InvalidKeyException(UNSUPPORTED_CURVE_MSG);
        }
        return c.getId();
    }

    @Override
    protected EcPublicJwk createJwkFromKey(JwkContext<ECPublicKey> ctx) {

        ECPublicKey key = ctx.getKey();

        ECParameterSpec spec = key.getParams();
        EllipticCurve curve = spec.getCurve();
        ECPoint point = key.getW();

        String curveId = getJwaIdByCurve(curve);
        if (!ECCurve.contains(curve, point)) {
            String msg = keyContainsErrorMessage(curveId);
            throw new InvalidKeyException(msg);
        }

        ctx.put(DefaultEcPublicJwk.CRV.getId(), curveId);

        int fieldSize = curve.getField().getFieldSize();
        String x = toOctetString(fieldSize, point.getAffineX());
        ctx.put(DefaultEcPublicJwk.X.getId(), x);

        String y = toOctetString(fieldSize, point.getAffineY());
        ctx.put(DefaultEcPublicJwk.Y.getId(), y);

        return new DefaultEcPublicJwk(ctx);
    }

    @Override
    protected EcPublicJwk createJwkFromValues(final JwkContext<ECPublicKey> ctx) {

        ParameterReadable reader = new RequiredParameterReader(ctx);
        String curveId = reader.get(DefaultEcPublicJwk.CRV);
        BigInteger x = reader.get(DefaultEcPublicJwk.X);
        BigInteger y = reader.get(DefaultEcPublicJwk.Y);

        ECCurve curve = getCurveByJwaId(curveId);
        ECPoint point = new ECPoint(x, y);

        if (!curve.contains(point)) {
            String msg = jwkContainsErrorMessage(curveId, ctx);
            throw new InvalidKeyException(msg);
        }

        final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, curve.toParameterSpec());
        ECPublicKey key = generateKey(ctx, new CheckedFunction<KeyFactory, ECPublicKey>() {
            @Override
            public ECPublicKey apply(KeyFactory kf) throws Exception {
                return (ECPublicKey) kf.generatePublic(pubSpec);
            }
        });

        ctx.setKey(key);

        return new DefaultEcPublicJwk(ctx);
    }
}

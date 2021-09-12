package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.InvalidKeyException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

class EcPublicJwkFactory extends AbstractEcJwkFactory<ECPublicKey, EcPublicJwk> {

    static final EcPublicJwkFactory DEFAULT_INSTANCE = new EcPublicJwkFactory();

    EcPublicJwkFactory() {
        super(ECPublicKey.class);
    }

    @Override
    protected EcPublicJwk createJwkFromKey(JwkContext<ECPublicKey> ctx) {

        ECPublicKey key = ctx.getKey();

        ECParameterSpec spec = key.getParams();
        EllipticCurve curve = spec.getCurve();
        ECPoint point = key.getW();

        String curveId = getJwaIdByCurve(curve);
        ctx.put(DefaultEcPublicJwk.CURVE_ID, curveId);

        int fieldSize = curve.getField().getFieldSize();
        String x = toOctetString(fieldSize, point.getAffineX());
        ctx.put(DefaultEcPublicJwk.X, x);

        String y = toOctetString(fieldSize, point.getAffineY());
        ctx.put(DefaultEcPublicJwk.Y, y);

        return new DefaultEcPublicJwk(ctx);
    }

    @Override
    protected EcPublicJwk createJwkFromValues(final JwkContext<ECPublicKey> ctx) {

        String curveId = getRequiredString(ctx, DefaultEcPublicJwk.CURVE_ID);
        BigInteger x = getRequiredBigInt(ctx, DefaultEcPublicJwk.X, false);
        BigInteger y = getRequiredBigInt(ctx, DefaultEcPublicJwk.Y, false);

        ECParameterSpec spec = getCurveByJwaId(curveId);
        ECPoint point = new ECPoint(x, y);

        if (!contains(spec.getCurve(), point)) {
            String msg = "EC JWK x,y coordinates do not match a point on the '" + curveId + "' elliptic curve. This " +
                "could be due simply to an incorrectly-created JWK or possibly an attempted Invalid Curve Attack " +
                "(see https://safecurves.cr.yp.to/twist.html for more information). JWK: {" + ctx + "}.";
            throw new InvalidKeyException(msg);
        }

        final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);

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

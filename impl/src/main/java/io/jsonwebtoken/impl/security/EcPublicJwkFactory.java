package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ValueGetter;
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

    private static final String KEY_CONTAINS_FORMAT_MSG =
        "ECPublicKey's ECPoint does not exist on elliptic curve '%s' and may not be used to create '%s' JWKs.";

    private static final String JWK_CONTAINS_FORMAT_MSG =
        "EC JWK x,y coordinates do not exist on elliptic curve '%s'. This " +
        "could be due simply to an incorrectly-created JWK or possibly an attempted Invalid Curve Attack " +
        "(see https://safecurves.cr.yp.to/twist.html for more information). JWK: %s";

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
        if (!contains(curve, point)) {
            String msg = String.format(KEY_CONTAINS_FORMAT_MSG, curveId, curveId);
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

        ValueGetter getter = new DefaultValueGetter(ctx);
        String curveId = getter.getRequiredString(DefaultEcPublicJwk.CRV.getId());
        BigInteger x = getter.getRequiredBigInt(DefaultEcPublicJwk.X.getId(), false);
        BigInteger y = getter.getRequiredBigInt(DefaultEcPublicJwk.Y.getId(), false);

        ECParameterSpec spec = getCurveByJwaId(curveId);
        ECPoint point = new ECPoint(x, y);

        if (!contains(spec.getCurve(), point)) {
            String msg = String.format(JWK_CONTAINS_FORMAT_MSG, curveId, ctx);
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

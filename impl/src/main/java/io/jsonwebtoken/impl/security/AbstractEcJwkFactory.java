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
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Curve;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

abstract class AbstractEcJwkFactory<K extends Key & ECKey, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final String UNSUPPORTED_CURVE_MSG = "The specified ECKey curve does not match a JWA standard curve id.";

    protected static ECParameterSpec getCurveByJwaId(String jwaCurveId) {
        ECParameterSpec spec = null;
        Curve curve = Curves.findById(jwaCurveId);
        if (curve instanceof ECCurve) {
            ECCurve ecCurve = (ECCurve) curve;
            spec = ecCurve.toParameterSpec();
        }
        if (spec == null) {
            String msg = "Unrecognized JWA curve id '" + jwaCurveId + "'";
            throw new UnsupportedKeyException(msg);
        }
        return spec;
    }

    protected static String getJwaIdByCurve(EllipticCurve curve) {
        ECCurve c = Curves.findBy(curve);
        if (c == null) {
            throw new UnsupportedKeyException(UNSUPPORTED_CURVE_MSG);
        }
        return c.getId();
    }

    /**
     * https://tools.ietf.org/html/rfc7518#section-6.2.1.2 indicates that this algorithm logic is defined in
     * http://www.secg.org/sec1-v2.pdf Section 2.3.5.
     *
     * @param fieldSize  EC field size
     * @param coordinate EC point coordinate (e.g. x or y)
     * @return A base64Url-encoded String representing the EC field element per the RFC format
     */
    // Algorithm defined in http://www.secg.org/sec1-v2.pdf Section 2.3.5
    static String toOctetString(int fieldSize, BigInteger coordinate) {
        byte[] bytes = Converters.BIGINT_UBYTES.applyTo(coordinate);
        int mlen = (int) Math.ceil(fieldSize / 8d);
        if (mlen > bytes.length) {
            byte[] m = new byte[mlen];
            System.arraycopy(bytes, 0, m, mlen - bytes.length, bytes.length);
            bytes = m;
        }
        return Encoders.BASE64URL.encode(bytes);
    }

    /**
     * Returns {@code true} if a given elliptic {@code curve} contains the specified {@code point}, {@code false}
     * otherwise.  Assumes elliptic curves over finite fields adhering to the reduced (a.k.a short or narrow)
     * Weierstrass form:
     * <p>
     * <code>y<sup>2</sup> = x<sup>3</sup> + ax + b</code>
     * </p>
     *
     * @param curve the Elliptic Curve to check
     * @param point a point that may or may not be defined on the specified elliptic curve
     * @return {@code true} if a given elliptic curve contains the specified {@code point}, {@code false} otherwise.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    static boolean contains(EllipticCurve curve, ECPoint point) {

        if (ECPoint.POINT_INFINITY.equals(point)) {
            return false;
        }

        final BigInteger a = curve.getA();
        final BigInteger b = curve.getB();
        final BigInteger x = point.getAffineX();
        final BigInteger y = point.getAffineY();

        // The reduced Weierstrass form y^2 = x^3 + ax + b reflects an elliptic curve E over any field K (e.g. all real
        // numbers or all complex numbers, etc). For computational simplicity, cryptographic (e.g. NIST) elliptic curves
        // restrict K to be a field of integers modulo a prime number 'p'.  As such, we apply modulo p (the field prime)
        // to the equation to account for the restricted field.  For a nice overview of the math behind EC curves and
        // their application in cryptography, see
        // https://web.northeastern.edu/dummit/docs/cryptography_5_elliptic_curves_in_cryptography.pdf

        final BigInteger p = ((ECFieldFp) curve.getField()).getP();

        // Verify the point coordinates are in field range:
        if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(p) >= 0 ||
            y.compareTo(BigInteger.ZERO) < 0 || y.compareTo(p) >= 0) {
            return false;
        }

        // Finally, assert Weierstrass form equality:
        final BigInteger lhs = y.modPow(TWO, p); //mod p to account for field prime
        final BigInteger rhs = x.modPow(THREE, p).add(a.multiply(x)).add(b).mod(p); //mod p to account for field prime
        return lhs.equals(rhs);
    }

    /**
     * Multiply a point {@code p} by scalar {@code s} on the curve identified by {@code spec}.
     *
     * @param p    the Elliptic Curve point to multiply
     * @param s    the scalar value to multiply
     * @param spec the domain parameters that identify the Elliptic Curve containing point {@code p}.
     */
    private static ECPoint multiply(ECPoint p, BigInteger s, ECParameterSpec spec) {
        if (ECPoint.POINT_INFINITY.equals(p)) {
            return p;
        }

        EllipticCurve curve = spec.getCurve();
        BigInteger n = spec.getOrder();
        BigInteger k = s.mod(n);

        ECPoint r0 = ECPoint.POINT_INFINITY;
        ECPoint r1 = p;

        // Montgomery Ladder implementation to mitigate side-channel attacks (i.e. an 'add' operation and a 'double'
        // operation is calculated for every loop iteration, regardless if the 'add'' is needed or not)
        // See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
//        while (k.compareTo(BigInteger.ZERO) > 0) {
//            ECPoint temp = add(r0, r1, curve);
//            r0 = k.testBit(0) ? temp : r0;
//            r1 = doublePoint(r1, curve);
//            k = k.shiftRight(1);
//        }
        // above implementation (k.compareTo/k.shiftRight) works correctly , but this is a little faster:
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            if (k.testBit(i)) { // bit == 1
                r0 = add(r0, r1, curve);
                r1 = doublePoint(r1, curve);
            } else { // bit == 0
                r1 = add(r0, r1, curve);
                r0 = doublePoint(r0, curve);
            }
        }

        return r0;
    }

    private static ECPoint add(ECPoint P, ECPoint Q, EllipticCurve curve) {

        if (ECPoint.POINT_INFINITY.equals(P)) {
            return Q;
        } else if (ECPoint.POINT_INFINITY.equals(Q)) {
            return P;
        } else if (P.equals(Q)) {
            return doublePoint(P, curve);
        }

        final BigInteger Px = P.getAffineX();
        final BigInteger Py = P.getAffineY();
        final BigInteger Qx = Q.getAffineX();
        final BigInteger Qy = Q.getAffineY();
        final BigInteger prime = ((ECFieldFp) curve.getField()).getP();
        final BigInteger slope = Qy.subtract(Py).multiply(Qx.subtract(Px).modInverse(prime)).mod(prime);
        final BigInteger Rx = slope.pow(2).subtract(Px).subtract(Qx).mod(prime);
        final BigInteger Ry = slope.multiply(Px.subtract(Rx)).subtract(Py).mod(prime);

        return new ECPoint(Rx, Ry);
    }

    private static ECPoint doublePoint(ECPoint P, EllipticCurve curve) {

        if (ECPoint.POINT_INFINITY.equals(P)) {
            return P;
        }

        final BigInteger Px = P.getAffineX();
        final BigInteger Py = P.getAffineY();
        final BigInteger p = ((ECFieldFp) curve.getField()).getP();
        final BigInteger a = curve.getA();
        final BigInteger s = THREE.multiply(Px.pow(2)).add(a).mod(p).multiply(TWO.multiply(Py).modInverse(p)).mod(p);
        final BigInteger x = s.pow(2).subtract(TWO.multiply(Px)).mod(p);
        final BigInteger y = s.multiply(Px.subtract(x)).subtract(Py).mod(p);

        return new ECPoint(x, y);
    }

    AbstractEcJwkFactory(Class<K> keyType, Set<Field<?>> fields) {
        super(DefaultEcPublicJwk.TYPE_VALUE, keyType, fields);
    }

    // visible for testing
    protected ECPublicKey derivePublic(KeyFactory keyFactory, ECPublicKeySpec spec) throws InvalidKeySpecException {
        return (ECPublicKey) keyFactory.generatePublic(spec);
    }

    protected ECPublicKey derivePublic(final JwkContext<ECPrivateKey> ctx) {
        final ECPrivateKey key = ctx.getKey();
        final ECParameterSpec params = key.getParams();
        final ECPoint w = multiply(params.getGenerator(), key.getS(), params);
        final ECPublicKeySpec spec = new ECPublicKeySpec(w, params);
        return generateKey(ctx, ECPublicKey.class, new CheckedFunction<KeyFactory, ECPublicKey>() {
            @Override
            public ECPublicKey apply(KeyFactory kf) {
                try {
                    return derivePublic(kf, spec);
                } catch (Exception e) {
                    String msg = "Unable to derive ECPublicKey from ECPrivateKey: " + e.getMessage();
                    throw new UnsupportedKeyException(msg, e);
                }
            }
        });
    }
}

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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class ECCurve extends AbstractCurve {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    static final String KEY_PAIR_GENERATOR_JCA_NAME = "EC";

    public static final ECCurve P256 = new ECCurve("P-256", "secp256r1"); // JDK standard
    public static final ECCurve P384 = new ECCurve("P-384", "secp384r1"); // JDK standard
    public static final ECCurve P521 = new ECCurve("P-521", "secp521r1"); // JDK standard

    public static final Collection<ECCurve> VALUES = Collections.setOf(P256, P384, P521);
    private static final Map<String, ECCurve> BY_ID = new LinkedHashMap<>(3);
    private static final Map<EllipticCurve, ECCurve> BY_JCA_CURVE = new LinkedHashMap<>(3);

    static {
        for (ECCurve curve : VALUES) {
            BY_ID.put(curve.getId(), curve);
        }
        for (ECCurve curve : VALUES) {
            BY_JCA_CURVE.put(curve.spec.getCurve(), curve);
        }
    }

    static EllipticCurve assertJcaCurve(ECKey key) {
        Assert.notNull(key, "ECKey cannot be null.");
        ECParameterSpec spec = Assert.notNull(key.getParams(), "ECKey params() cannot be null.");
        return Assert.notNull(spec.getCurve(), "ECKey params().getCurve() cannot be null.");
    }

    static ECCurve findById(String id) {
        return BY_ID.get(id);
    }

    static ECCurve findByJcaCurve(EllipticCurve curve) {
        return BY_JCA_CURVE.get(curve);
    }

    static ECCurve findByKey(Key key) {
        if (!(key instanceof ECKey)) {
            return null;
        }
        ECKey ecKey = (ECKey) key;
        ECParameterSpec spec = ecKey.getParams();
        if (spec == null) {
            return null;
        }
        EllipticCurve jcaCurve = spec.getCurve();
        ECCurve curve = BY_JCA_CURVE.get(jcaCurve);
        if (curve != null && key instanceof ECPublicKey) {
            ECPublicKey pub = (ECPublicKey) key;
            ECPoint w = pub.getW();
            if (w == null || !curve.contains(w)) { // don't support keys with a point not on its indicated curve
                curve = null;
            }
        }
        return curve;
    }

    static ECPublicKeySpec publicKeySpec(ECPrivateKey key) throws IllegalArgumentException {
        EllipticCurve jcaCurve = assertJcaCurve(key);
        ECCurve curve = BY_JCA_CURVE.get(jcaCurve);
        Assert.notNull(curve, "There is no JWA-standard Elliptic Curve for specified ECPrivateKey.");
        final ECPoint w = curve.multiply(key.getS());
        return new ECPublicKeySpec(w, curve.spec);
    }

    private final ECParameterSpec spec;

    public ECCurve(String id, String jcaName) {
        super(id, jcaName);
        JcaTemplate template = new JcaTemplate(KEY_PAIR_GENERATOR_JCA_NAME);
        this.spec = template.withAlgorithmParameters(new CheckedFunction<AlgorithmParameters, ECParameterSpec>() {
            @Override
            public ECParameterSpec apply(AlgorithmParameters params) throws Exception {
                params.init(new ECGenParameterSpec(getJcaName()));
                return params.getParameterSpec(ECParameterSpec.class);
            }
        });
    }

    public ECParameterSpec toParameterSpec() {
        return this.spec;
    }

    @Override
    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(KEY_PAIR_GENERATOR_JCA_NAME, toParameterSpec());
    }

    @Override
    public boolean contains(Key key) {
        if (key instanceof ECPublicKey) {
            ECPublicKey pub = (ECPublicKey) key;
            ECParameterSpec pubSpec = pub.getParams();
            return pubSpec != null &&
                    this.spec.getCurve().equals(pubSpec.getCurve()) &&
                    contains(pub.getW());

        }
        return false;
    }

    boolean contains(ECPoint point) {
        return contains(this.spec.getCurve(), point);
    }

    /**
     * Returns {@code true} if the specified curve contains the specified {@code point}, {@code false} otherwise.
     * Assumes elliptic curves over finite fields adhering to the reduced (a.k.a short or narrow)
     * Weierstrass form:
     * <p>
     * <code>y<sup>2</sup> = x<sup>3</sup> + ax + b</code>
     * </p>
     *
     * @param curve the EllipticCurve to check
     * @param point a point that may or may not be defined on this elliptic curve
     * @return {@code true} if this curve contains the specified {@code point}, {@code false} otherwise.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    static boolean contains(EllipticCurve curve, ECPoint point) {

        if (point == null || ECPoint.POINT_INFINITY.equals(point)) {
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
     * Multiply this curve's generator (aka 'base point') by scalar {@code s} on the curve.
     *
     * @param s the scalar value to multiply
     */
    private ECPoint multiply(BigInteger s) {
        return multiply(this.spec.getGenerator(), s);
    }

    /**
     * Multiply a point {@code p} by scalar {@code s} on the curve.
     *
     * @param p the Elliptic Curve point to multiply
     * @param s the scalar value to multiply
     */
    private ECPoint multiply(ECPoint p, BigInteger s) {

        if (ECPoint.POINT_INFINITY.equals(p)) {
            return p;
        }

        final BigInteger n = this.spec.getOrder();
        final BigInteger k = s.mod(n);

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
                r0 = add(r0, r1);
                r1 = doublePoint(r1);
            } else { // bit == 0
                r1 = add(r0, r1);
                r0 = doublePoint(r0);
            }
        }

        return r0;
    }

    private ECPoint add(ECPoint P, ECPoint Q) {

        if (ECPoint.POINT_INFINITY.equals(P)) {
            return Q;
        } else if (ECPoint.POINT_INFINITY.equals(Q)) {
            return P;
        } else if (P.equals(Q)) {
            return doublePoint(P);
        }

        final EllipticCurve curve = this.spec.getCurve();

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

    private ECPoint doublePoint(ECPoint P) {

        if (ECPoint.POINT_INFINITY.equals(P)) {
            return P;
        }

        final EllipticCurve curve = this.spec.getCurve();
        final BigInteger Px = P.getAffineX();
        final BigInteger Py = P.getAffineY();
        final BigInteger p = ((ECFieldFp) curve.getField()).getP();
        final BigInteger a = curve.getA();
        final BigInteger s = THREE.multiply(Px.pow(2)).add(a).mod(p).multiply(TWO.multiply(Py).modInverse(p)).mod(p);
        final BigInteger x = s.pow(2).subtract(TWO.multiply(Px)).mod(p);
        final BigInteger y = s.multiply(Px.subtract(x)).subtract(Py).mod(p);

        return new ECPoint(x, y);
    }
}

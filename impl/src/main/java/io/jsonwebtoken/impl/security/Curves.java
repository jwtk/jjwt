/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.DefaultRegistry;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;

import java.security.spec.EllipticCurve;
import java.util.Collection;
import java.util.LinkedHashSet;

public final class Curves {
    public static final Curve P_256 = new ECCurve("P-256", "secp256r1"); // JDK standard
    public static final Curve P_384 = new ECCurve("P-384", "secp384r1"); // JDK standard
    public static final Curve P_521 = new ECCurve("P-521", "secp521r1"); // JDK standard
    public static final EdwardsCurve X25519 = EdwardsCurve.X25519;
    public static final EdwardsCurve X448 = EdwardsCurve.X448;
    public static final EdwardsCurve Ed25519 = EdwardsCurve.Ed25519;
    public static final EdwardsCurve Ed448 = EdwardsCurve.Ed448;

    private static final Collection<ECCurve> EC_CURVES = Collections.setOf((ECCurve) P_256, (ECCurve) P_384, (ECCurve) P_521);

    private static final Collection<Curve> VALUES = new LinkedHashSet<>();

    static {
        VALUES.addAll(EC_CURVES);
        VALUES.addAll(EdwardsCurve.VALUES);
    }

    private static final Registry<String, Curve> CURVES_BY_ID = new IdRegistry<>(VALUES);
    private static final Registry<String, Curve> CURVES_BY_JCA_NAME = new DefaultRegistry<>(VALUES, new Function<Curve, String>() {
        @Override
        public String apply(Curve curve) {
            return ((DefaultCurve) curve).getJcaName();
        }
    });

    private static final Registry<EllipticCurve, ECCurve> CURVES_BY_JCA_CURVE = new DefaultRegistry<>(EC_CURVES, new Function<ECCurve, EllipticCurve>() {
        @Override
        public EllipticCurve apply(ECCurve curve) {
            return curve.toParameterSpec().getCurve();
        }
    });

    //prevent instantiation
    private Curves() {
    }

    public static Curve findById(String jwaId) {
        Assert.hasText(jwaId, "jwaId cannot be null or empty.");
        return CURVES_BY_ID.apply(jwaId);
    }

    public static Curve findByJcaName(String jcaName) {
        Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        return CURVES_BY_JCA_NAME.apply(jcaName);
    }

    public static ECCurve findBy(EllipticCurve curve) {
        Assert.notNull(curve, "EllipticCurve argument cannot be null.");
        return CURVES_BY_JCA_CURVE.apply(curve);
    }
}

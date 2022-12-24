package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.impl.lang.DefaultRegistry;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;

import java.security.KeyPairGenerator;
import java.security.spec.EllipticCurve;
import java.util.Collection;
import java.util.LinkedHashSet;

public final class Curves {

    public static final Curve P_256 = new ECCurve("P-256", "secp256r1"); // JDK standard
    public static final Curve P_384 = new ECCurve("P-384", "secp384r1"); // JDK standard
    public static final Curve P_521 = new ECCurve("P-521", "secp521r1"); // JDK standard
    public static final Curve X25519 = edwards("X25519"); // >= JDK 11 or BC is needed
    public static final Curve X448 = edwards("X448"); // >= JDK 11 or BC is needed
    public static final Curve Ed25519 = edwards("Ed25519"); // >= JDK 15 or BC is needed
    public static final Curve Ed448 = edwards("Ed448"); // >= JDK 15 or BC is needed

    private static Curve edwards(final String name) {
        return new DefaultCurve(name, name, // JWT ID and JCA name happen to be identical
                // fall back to BouncyCastle if >= JDK 11 (for XDH curves) or 15 (for EdDSA curves) if necessary:
                Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<KeyPairGenerator>() {
                            @Override
                            public KeyPairGenerator get() throws Exception {
                                return KeyPairGenerator.getInstance(name);
                            }
                        })
                ));
    }

    private static final Collection<ECCurve> EC_CURVES = Collections.setOf((ECCurve) P_256, (ECCurve) P_384, (ECCurve) P_521);

    private static final Collection<Curve> EDWARDS_CURVES = Collections.setOf(Ed25519, Ed448, X25519, X448);
    private static final Collection<Curve> VALUES = new LinkedHashSet<>();

    static {
        VALUES.addAll(EC_CURVES);
        VALUES.addAll(EDWARDS_CURVES);
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

/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * ElliptiCurve crypto provider.
 *
 * @since 0.5
 */
public abstract class EllipticCurveProvider extends SignatureProvider {

    private static final Map<SignatureAlgorithm, String> EC_CURVE_NAMES = createEcCurveNames();

    private static Map<SignatureAlgorithm, String> createEcCurveNames() {
        Map<SignatureAlgorithm, String> m = new HashMap<SignatureAlgorithm, String>(); //alg to ASN1 OID name
        m.put(SignatureAlgorithm.ES256, "secp256r1");
        m.put(SignatureAlgorithm.ES384, "secp384r1");
        m.put(SignatureAlgorithm.ES512, "secp521r1");
        return m;
    }

    protected EllipticCurveProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isEllipticCurve(), "SignatureAlgorithm must be an Elliptic Curve algorithm.");
    }

    /**
     * Generates a new secure-random key pair assuming strength enough for the {@link
     * SignatureAlgorithm#ES512} algorithm. This is a convenience method that immediately delegates to {@link
     * #generateKeyPair(SignatureAlgorithm)} using {@link SignatureAlgorithm#ES512} as the method argument.
     *
     * @return a new secure-randomly-generated key pair assuming strength enough for the {@link
     * SignatureAlgorithm#ES512} algorithm.
     * @see #generateKeyPair(SignatureAlgorithm)
     * @see #generateKeyPair(SignatureAlgorithm, SecureRandom)
     * @see #generateKeyPair(String, String, SignatureAlgorithm, SecureRandom)
     */
    public static KeyPair generateKeyPair() {
        return generateKeyPair(SignatureAlgorithm.ES512);
    }

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using JJWT's default {@link
     * SignatureProvider#DEFAULT_SECURE_RANDOM SecureRandom instance}.  This is a convenience method that immediately
     * delegates to {@link #generateKeyPair(SignatureAlgorithm, SecureRandom)}.
     *
     * @param alg the algorithm indicating strength, must be one of {@code ES256}, {@code ES384} or {@code ES512}
     * @return a new secure-randomly generated key pair of sufficient strength for the specified {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using JJWT's default {@link
     * SignatureProvider#DEFAULT_SECURE_RANDOM SecureRandom instance}.
     * @see #generateKeyPair()
     * @see #generateKeyPair(SignatureAlgorithm, SecureRandom)
     * @see #generateKeyPair(String, String, SignatureAlgorithm, SecureRandom)
     */
    public static KeyPair generateKeyPair(SignatureAlgorithm alg) {
        return generateKeyPair(alg, SignatureProvider.DEFAULT_SECURE_RANDOM);
    }

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator.  This is a convenience method that immediately delegates to {@link
     * #generateKeyPair(String, String, SignatureAlgorithm, SecureRandom)} using {@code "ECDSA"} as the {@code
     * jcaAlgorithmName} and {@code "BC"} as the {@code jcaProviderName} since EllipticCurve requires the use of an
     * external JCA provider ({@code BC stands for BouncyCastle}.  This will work as expected as long as the
     * BouncyCastle dependency is in the runtime classpath.
     *
     * @param alg    alg the algorithm indicating strength, must be one of {@code ES256}, {@code ES384} or {@code
     *               ES512}
     * @param random the SecureRandom generator to use during key generation.
     * @return a new secure-randomly generated key pair of sufficient strength for the specified {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator.
     * @see #generateKeyPair()
     * @see #generateKeyPair(SignatureAlgorithm)
     * @see #generateKeyPair(String, String, SignatureAlgorithm, SecureRandom)
     */
    public static KeyPair generateKeyPair(SignatureAlgorithm alg, SecureRandom random) {
        return generateKeyPair("ECDSA", "BC", alg, random);
    }

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator via the specified JCA provider and algorithm name.
     *
     * @param jcaAlgorithmName the JCA name of the algorithm to use for key pair generation, for example, {@code
     *                         ECDSA}.
     * @param jcaProviderName  the JCA provider name of the algorithm implementation, for example {@code BC} for
     *                         BouncyCastle.
     * @param alg              alg the algorithm indicating strength, must be one of {@code ES256}, {@code ES384} or
     *                         {@code ES512}
     * @param random           the SecureRandom generator to use during key generation.
     * @return a new secure-randomly generated key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator via the specified JCA provider and algorithm name.
     * @see #generateKeyPair()
     * @see #generateKeyPair(SignatureAlgorithm)
     * @see #generateKeyPair(SignatureAlgorithm, SecureRandom)
     */
    public static KeyPair generateKeyPair(String jcaAlgorithmName, String jcaProviderName, SignatureAlgorithm alg,
                                          SecureRandom random) {
        Assert.notNull(alg, "SignatureAlgorithm argument cannot be null.");
        Assert.isTrue(alg.isEllipticCurve(), "SignatureAlgorithm argument must represent an Elliptic Curve algorithm.");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(jcaAlgorithmName, jcaProviderName);
            String paramSpecCurveName = EC_CURVE_NAMES.get(alg);
            g.initialize(org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(paramSpecCurveName), random);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate Elliptic Curve KeyPair: " + e.getMessage(), e);
        }
    }
}

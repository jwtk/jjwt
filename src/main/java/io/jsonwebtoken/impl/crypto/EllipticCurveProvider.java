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

    public static KeyPair generateKeyPair() {
        return generateKeyPair(SignatureAlgorithm.ES512);
    }

    public static KeyPair generateKeyPair(SignatureAlgorithm alg) {
        return generateKeyPair(alg, SignatureProvider.DEFAULT_SECURE_RANDOM);
    }

    public static KeyPair generateKeyPair(SignatureAlgorithm alg, SecureRandom random) {
        return generateKeyPair("ECDSA", "BC", alg, random);
    }

    public static KeyPair generateKeyPair(String jcaAlgorithmName, String jcaProviderName, SignatureAlgorithm alg, SecureRandom random) {
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

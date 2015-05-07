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
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.lang.Assert;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

abstract class EllipticCurveProvider extends SignatureProvider {

    private static final Map<SignatureAlgorithm, String> EC_SIG_ALG_NAMES = createEcSigAlgNames();

    private static Map<SignatureAlgorithm, String> createEcSigAlgNames() {
        Map<SignatureAlgorithm, String> m =
            new HashMap<SignatureAlgorithm, String>(); //EC alg name to EC alg signature name
        m.put(SignatureAlgorithm.ES256, "SHA256withECDSA");
        m.put(SignatureAlgorithm.ES384, "SHA384withECDSA");
        m.put(SignatureAlgorithm.ES512, "SHA512withECDSA");
        return m;
    }

    protected EllipticCurveProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isEllipticCurve(), "SignatureAlgorithm must be an Elliptic Curve algorithm.");
    }

    protected Signature createSignatureInstance() {
        return newSignatureInstance();
    }

    protected Signature newSignatureInstance() {
        try {
            String sigAlgName = EC_SIG_ALG_NAMES.get(alg);
            if (sigAlgName == null) {
                throw new NoSuchAlgorithmException("No EllipticCurve signature algorithm for algorithm " + alg +
                                                   ".  This is a bug.  Please report this to the project issue tracker.");
            }
            return Signature.getInstance(sigAlgName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unavailable Elliptic Curve Signature algorithm.";
            if (!alg.isJdkStandard()) {
                msg += " This is not a standard JDK algorithm. Try including BouncyCastle in the runtime classpath.";
            }
            throw new SignatureException(msg, e);
        }
    }
}

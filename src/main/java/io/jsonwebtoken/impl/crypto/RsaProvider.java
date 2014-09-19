/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

abstract class RsaProvider extends SignatureProvider {

    protected RsaProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isRsa(), "SignatureAlgorithm must be an RSASSA or RSASSA-PSS algorithm.");
    }

    protected Signature createSignatureInstance() {

        Signature sig = newSignatureInstance();

        if (alg.name().startsWith("PS")) {

            MGF1ParameterSpec paramSpec;
            int saltLength;

            switch (alg) {
                case PS256:
                    paramSpec = MGF1ParameterSpec.SHA256;
                    saltLength = 32;
                    break;
                case PS384:
                    paramSpec = MGF1ParameterSpec.SHA384;
                    saltLength = 48;
                    break;
                case PS512:
                    paramSpec = MGF1ParameterSpec.SHA512;
                    saltLength = 64;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported RSASSA-PSS algorithm: " + alg);
            }

            PSSParameterSpec pssParamSpec =
                new PSSParameterSpec(paramSpec.getDigestAlgorithm(), "MGF1", paramSpec, saltLength, 1);

            setParameter(sig, pssParamSpec);
        }

        return sig;
    }

    protected Signature newSignatureInstance() {
        try {
            return Signature.getInstance(alg.getJcaName());
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unavailable RSA Signature algorithm.";
            if (!alg.isJdkStandard()) {
                msg += " This is not a standard JDK algorithm. Try including BouncyCastle in the runtime classpath.";
            }
            throw new SignatureException(msg, e);
        }
    }

    protected void setParameter(Signature sig, PSSParameterSpec spec) {
        try {
            sig.setParameter(spec);
        } catch (InvalidAlgorithmParameterException e) {
            String msg = "Unsupported RSASSA-PSS parameter '" + spec + "': " + e.getMessage();
            throw new SignatureException(msg, e);
        }

    }
}

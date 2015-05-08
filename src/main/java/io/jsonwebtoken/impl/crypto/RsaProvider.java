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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;

public abstract class RsaProvider extends SignatureProvider {

    private static final Map<SignatureAlgorithm, PSSParameterSpec> PSS_PARAMETER_SPECS = createPssParameterSpecs();

    private static Map<SignatureAlgorithm, PSSParameterSpec> createPssParameterSpecs() {

        Map<SignatureAlgorithm, PSSParameterSpec> m = new HashMap<SignatureAlgorithm, PSSParameterSpec>();

        MGF1ParameterSpec ps = MGF1ParameterSpec.SHA256;
        PSSParameterSpec spec = new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, 32, 1);
        m.put(SignatureAlgorithm.PS256, spec);

        ps = MGF1ParameterSpec.SHA384;
        spec = new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, 48, 1);
        m.put(SignatureAlgorithm.PS384, spec);

        ps = MGF1ParameterSpec.SHA512;
        spec = new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, 64, 1);
        m.put(SignatureAlgorithm.PS512, spec);

        return m;
    }

    protected RsaProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isRsa(), "SignatureAlgorithm must be an RSASSA or RSASSA-PSS algorithm.");
    }

    protected Signature createSignatureInstance() {

        Signature sig = super.createSignatureInstance();

        PSSParameterSpec spec = PSS_PARAMETER_SPECS.get(alg);
        if (spec != null) {
            setParameter(sig, spec);
        }
        return sig;
    }

    protected void setParameter(Signature sig, PSSParameterSpec spec) {
        try {
            doSetParameter(sig, spec);
        } catch (InvalidAlgorithmParameterException e) {
            String msg = "Unsupported RSASSA-PSS parameter '" + spec + "': " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected void doSetParameter(Signature sig, PSSParameterSpec spec) throws InvalidAlgorithmParameterException {
        sig.setParameter(spec);
    }

    public static KeyPair generateKeyPair() {
        return generateKeyPair(4096);
    }

    public static KeyPair generateKeyPair(int keySizeInBits) {
        return generateKeyPair(keySizeInBits, SignatureProvider.DEFAULT_SECURE_RANDOM);
    }

    public static KeyPair generateKeyPair(int keySizeInBits, SecureRandom random) {
        return generateKeyPair("RSA", keySizeInBits, random);
    }

    protected static KeyPair generateKeyPair(String jcaAlgName, int keySizeInBits, SecureRandom random) {
        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance(jcaAlgName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to obtain an RSA KeyPairGenerator: " + e.getMessage(), e);
        }

        keyGenerator.initialize(keySizeInBits, random);

        return keyGenerator.genKeyPair();
    }

}

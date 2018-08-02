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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.SignatureException;

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

    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible(); //PS256, PS384, PS512 on <= JDK 10 require BC
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

    /**
     * Generates a new RSA secure-random 4096 bit key pair.  4096 bits is JJWT's current recommended minimum key size
     * for use in modern applications (during or after year 2015).  This is a convenience method that immediately
     * delegates to {@link #generateKeyPair(int)}.
     *
     * @return a new RSA secure-random 4096 bit key pair.
     * @see #generateKeyPair(int)
     * @see #generateKeyPair(int, SecureRandom)
     * @see #generateKeyPair(String, int, SecureRandom)
     * @since 0.5
     */
    public static KeyPair generateKeyPair() {
        return generateKeyPair(4096);
    }

    /**
     * Generates a new RSA secure-randomly key pair of the specified size using JJWT's default {@link
     * SignatureProvider#DEFAULT_SECURE_RANDOM SecureRandom instance}.  This is a convenience method that immediately
     * delegates to {@link #generateKeyPair(int, SecureRandom)}.
     *
     * @param keySizeInBits the key size in bits (<em>NOT bytes</em>).
     * @return a new RSA secure-random key pair of the specified size.
     * @see #generateKeyPair()
     * @see #generateKeyPair(int, SecureRandom)
     * @see #generateKeyPair(String, int, SecureRandom)
     * @since 0.5
     */
    public static KeyPair generateKeyPair(int keySizeInBits) {
        return generateKeyPair(keySizeInBits, DEFAULT_SECURE_RANDOM);
    }

    /**
     * Generates a new RSA secure-randomly key pair suitable for the specified SignatureAlgorithm using JJWT's
     * default {@link SignatureProvider#DEFAULT_SECURE_RANDOM SecureRandom instance}.  This is a convenience method
     * that immediately delegates to {@link #generateKeyPair(int)} based on the relevant key size for the specified
     * algorithm.
     *
     * @param alg the signature algorithm to inspect to determine a size in bits.
     * @return a new RSA secure-random key pair of the specified size.
     * @see #generateKeyPair()
     * @see #generateKeyPair(int, SecureRandom)
     * @see #generateKeyPair(String, int, SecureRandom)
     * @since 0.10.0
     */
    @SuppressWarnings("unused") //used by io.jsonwebtoken.security.Keys
    public static KeyPair generateKeyPair(SignatureAlgorithm alg) {
        Assert.isTrue(alg.isRsa(), "Only RSA algorithms are supported by this method.");
        int keySizeInBits = 4096;
        switch (alg) {
            case RS256:
            case PS256:
                keySizeInBits = 2048;
                break;
            case RS384:
            case PS384:
                keySizeInBits = 3072;
                break;
        }
        return generateKeyPair(keySizeInBits, DEFAULT_SECURE_RANDOM);
    }

    /**
     * Generates a new RSA secure-random key pair of the specified size using the given SecureRandom number generator.
     * This is a convenience method that immediately delegates to {@link #generateKeyPair(String, int, SecureRandom)}
     * using {@code RSA} as the {@code jcaAlgorithmName} argument.
     *
     * @param keySizeInBits the key size in bits (<em>NOT bytes</em>)
     * @param random        the secure random number generator to use during key generation.
     * @return a new RSA secure-random key pair of the specified size using the given SecureRandom number generator.
     * @see #generateKeyPair()
     * @see #generateKeyPair(int)
     * @see #generateKeyPair(String, int, SecureRandom)
     * @since 0.5
     */
    public static KeyPair generateKeyPair(int keySizeInBits, SecureRandom random) {
        return generateKeyPair("RSA", keySizeInBits, random);
    }

    /**
     * Generates a new secure-random key pair of the specified size using the specified SecureRandom according to the
     * specified {@code jcaAlgorithmName}.
     *
     * @param jcaAlgorithmName the name of the JCA algorithm to use for key pair generation, for example, {@code RSA}.
     * @param keySizeInBits    the key size in bits (<em>NOT bytes</em>)
     * @param random           the SecureRandom generator to use during key generation.
     * @return a new secure-randomly generated key pair of the specified size using the specified SecureRandom according
     * to the specified {@code jcaAlgorithmName}.
     * @see #generateKeyPair()
     * @see #generateKeyPair(int)
     * @see #generateKeyPair(int, SecureRandom)
     * @since 0.5
     */
    protected static KeyPair generateKeyPair(String jcaAlgorithmName, int keySizeInBits, SecureRandom random) {
        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance(jcaAlgorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to obtain an RSA KeyPairGenerator: " + e.getMessage(), e);
        }

        keyGenerator.initialize(keySizeInBits, random);

        return keyGenerator.genKeyPair();
    }

}

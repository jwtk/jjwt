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

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
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
        return generateKeyPair(alg, DEFAULT_SECURE_RANDOM);
    }

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator.  This is a convenience method that immediately delegates to {@link
     * #generateKeyPair(String, String, SignatureAlgorithm, SecureRandom)} using {@code "EC"} as the {@code
     * jcaAlgorithmName}.
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
        return generateKeyPair("EC", null, alg, random);
    }

    /**
     * Generates a new secure-random key pair of sufficient strength for the specified Elliptic Curve {@link
     * SignatureAlgorithm} (must be one of {@code ES256}, {@code ES384} or {@code ES512}) using the specified {@link
     * SecureRandom} random number generator via the specified JCA provider and algorithm name.
     *
     * @param jcaAlgorithmName the JCA name of the algorithm to use for key pair generation, for example, {@code
     *                         ECDSA}.
     * @param jcaProviderName  the JCA provider name of the algorithm implementation (for example {@code "BC"} for
     *                         BouncyCastle) or {@code null} if the default provider should be used.
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
            KeyPairGenerator g;

            if (Strings.hasText(jcaProviderName)) {
                g = KeyPairGenerator.getInstance(jcaAlgorithmName, jcaProviderName);
            } else {
                g = KeyPairGenerator.getInstance(jcaAlgorithmName);
            }

            String paramSpecCurveName = EC_CURVE_NAMES.get(alg);
            ECGenParameterSpec spec = new ECGenParameterSpec(paramSpecCurveName);
            g.initialize(spec, random);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate Elliptic Curve KeyPair: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the expected signature byte array length (R + S parts) for
     * the specified ECDSA algorithm.
     *
     * @param alg The ECDSA algorithm. Must be supported and not
     *            {@code null}.
     * @return The expected byte array length for the signature.
     * @throws JwtException If the algorithm is not supported.
     */
    public static int getSignatureByteArrayLength(final SignatureAlgorithm alg)
        throws JwtException {

        switch (alg) {
            case ES256:
                return 64;
            case ES384:
                return 96;
            case ES512:
                return 132;
            default:
                throw new JwtException("Unsupported Algorithm: " + alg.name());
        }
    }


    /**
     * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
     * R + S format expected by ECDSA JWS.
     *
     * @param derSignature The ASN1./DER-encoded. Must not be {@code null}.
     * @param outputLength The expected length of the ECDSA JWS signature.
     * @return The ECDSA JWS encoded signature.
     * @throws JwtException If the ASN.1/DER signature format is invalid.
     */
    public static byte[] transcodeSignatureToConcat(final byte[] derSignature, int outputLength) throws JwtException {

        if (derSignature.length < 8 || derSignature[0] != 48) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;
        if (derSignature[1] > 0) {
            offset = 2;
        } else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new JwtException("Invalid ECDSA signature format");
        }

        byte rLength = derSignature[offset + 1];

        int i = rLength;
        while ((i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0)) {
            i--;
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j = sLength;
        while ((j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0)) {
            j--;
        }

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength / 2);

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
            || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
            || derSignature[offset] != 2
            || derSignature[offset + 2 + rLength] != 2) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        final byte[] concatSignature = new byte[2 * rawLen];

        System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
        System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

        return concatSignature;
    }


    /**
     * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
     * the JCA verifier.
     *
     * @param jwsSignature The JWS signature, consisting of the
     *                     concatenated R and S values. Must not be
     *                     {@code null}.
     * @return The ASN.1/DER encoded signature.
     * @throws JwtException If the ECDSA JWS signature format is invalid.
     */
    public static byte[] transcodeSignatureToDER(byte[] jwsSignature) throws JwtException {

        int rawLen = jwsSignature.length / 2;

        int i = rawLen;

        while ((i > 0) && (jwsSignature[rawLen - i] == 0)) {
            i--;
        }

        int j = i;

        if (jwsSignature[rawLen - i] < 0) {
            j += 1;
        }

        int k = rawLen;

        while ((k > 0) && (jwsSignature[2 * rawLen - k] == 0)) {
            k--;
        }

        int l = k;

        if (jwsSignature[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;

        if (len > 255) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;

        final byte derSignature[];

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }
}

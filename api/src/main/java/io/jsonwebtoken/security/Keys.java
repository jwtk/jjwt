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
package io.jsonwebtoken.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for securely generating {@link SecretKey}s and {@link KeyPair}s.
 *
 * @since 0.10.0
 */
public final class Keys {

    private static final String MAC = "io.jsonwebtoken.impl.crypto.MacProvider";
    private static final String RSA = "io.jsonwebtoken.impl.crypto.RsaProvider";
    private static final String EC = "io.jsonwebtoken.impl.crypto.EllipticCurveProvider";

    private static final Class[] SIG_ARG_TYPES = new Class[]{SignatureAlgorithm.class};

    //purposefully ordered higher to lower:
    private static final List<SignatureAlgorithm> PREFERRED_HMAC_ALGS = Collections.unmodifiableList(Arrays.asList(
        SignatureAlgorithm.HS512, SignatureAlgorithm.HS384, SignatureAlgorithm.HS256));

    //prevent instantiation
    private Keys() {
    }

    /*
    public static final int bitLength(Key key) throws IllegalArgumentException {
        Assert.notNull(key, "Key cannot be null.");
        if (key instanceof SecretKey) {
            byte[] encoded = key.getEncoded();
            return Arrays.length(encoded) * 8;
        } else if (key instanceof RSAKey) {
            return ((RSAKey)key).getModulus().bitLength();
        } else if (key instanceof ECKey) {
            return ((ECKey)key).getParams().getOrder().bitLength();
        }

        throw new IllegalArgumentException("Unsupported key type: " + key.getClass().getName());
    }
    */

    /**
     * Creates a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
     *
     * @param bytes the key byte array
     * @return a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
     * @throws WeakKeyException if the key byte array length is less than 256 bits (32 bytes) as mandated by the
     *                          <a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWT JWA Specification
     *                          (RFC 7518, Section 3.2)</a>
     */
    public static SecretKey hmacShaKeyFor(byte[] bytes) throws WeakKeyException {

        if (bytes == null) {
            throw new InvalidKeyException("SecretKey byte array cannot be null.");
        }

        int bitLength = bytes.length * 8;

        for (SignatureAlgorithm alg : PREFERRED_HMAC_ALGS) {
            if (bitLength >= alg.getMinKeyLength()) {
                return new SecretKeySpec(bytes, alg.getJcaName());
            }
        }

        String msg = "The specified key byte array is " + bitLength + " bits which " +
            "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " +
            "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " +
            "size >= 256 bits (the key size must be greater than or equal to the hash " +
            "output size).  Consider using the " + Keys.class.getName() + "#secretKeyFor(SignatureAlgorithm) method " +
            "to create a key guaranteed to be secure enough for your preferred HMAC-SHA algorithm.  See " +
            "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
        throw new WeakKeyException(msg);
    }

    /**
     * Returns a new {@link SecretKey} with a key length suitable for use with the specified {@link SignatureAlgorithm}.
     *
     * <p><a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518), Section 3.2</a>
     * requires minimum key lengths to be used for each respective Signature Algorithm.  This method returns a
     * secure-random generated SecretKey that adheres to the required minimum key length.  The lengths are:</p>
     *
     * <table>
     * <tr>
     * <th>Algorithm</th>
     * <th>Key Length</th>
     * </tr>
     * <tr>
     * <td>HS256</td>
     * <td>256 bits (32 bytes)</td>
     * </tr>
     * <tr>
     * <td>HS384</td>
     * <td>384 bits (48 bytes)</td>
     * </tr>
     * <tr>
     * <td>HS512</td>
     * <td>512 bits (64 bytes)</td>
     * </tr>
     * </table>
     *
     * @param alg the {@code SignatureAlgorithm} to inspect to determine which key length to use.
     * @return a new {@link SecretKey} instance suitable for use with the specified {@link SignatureAlgorithm}.
     * @throws IllegalArgumentException for any input value other than {@link SignatureAlgorithm#HS256},
     *                                  {@link SignatureAlgorithm#HS384}, or {@link SignatureAlgorithm#HS512}
     */
    public static SecretKey secretKeyFor(SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        switch (alg) {
            case HS256:
            case HS384:
            case HS512:
                return Classes.invokeStatic(MAC, "generateKey", SIG_ARG_TYPES, alg);
            default:
                String msg = "The " + alg.name() + " algorithm does not support shared secret keys.";
                throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Returns a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.
     *
     * <p>If the {@code alg} argument is an RSA algorithm, a KeyPair is generated based on the following:</p>
     *
     * <table>
     * <tr>
     * <th>JWA Algorithm</th>
     * <th>Key Size</th>
     * </tr>
     * <tr>
     * <td>RS256</td>
     * <td>2048 bits</td>
     * </tr>
     * <tr>
     * <td>PS256</td>
     * <td>2048 bits</td>
     * </tr>
     * <tr>
     * <td>RS384</td>
     * <td>3072 bits</td>
     * </tr>
     * <tr>
     * <td>PS384</td>
     * <td>3072 bits</td>
     * </tr>
     * <tr>
     * <td>RS512</td>
     * <td>4096 bits</td>
     * </tr>
     * <tr>
     * <td>PS512</td>
     * <td>4096 bits</td>
     * </tr>
     * </table>
     *
     * <p>If the {@code alg} argument is an Elliptic Curve algorithm, a KeyPair is generated based on the following:</p>
     *
     * <table>
     * <tr>
     * <th>JWA Algorithm</th>
     * <th>Key Size</th>
     * <th><a href="https://tools.ietf.org/html/rfc7518#section-7.6.2">JWA Curve Name</a></th>
     * <th><a href="https://tools.ietf.org/html/rfc5480#section-2.1.1.1">ASN1 OID Curve Name</a></th>
     * </tr>
     * <tr>
     * <td>EC256</td>
     * <td>256 bits</td>
     * <td>{@code P-256}</td>
     * <td>{@code secp256r1}</td>
     * </tr>
     * <tr>
     * <td>EC384</td>
     * <td>384 bits</td>
     * <td>{@code P-384}</td>
     * <td>{@code secp384r1}</td>
     * </tr>
     * <tr>
     * <td>EC512</td>
     * <td>512 bits</td>
     * <td>{@code P-521}</td>
     * <td>{@code secp521r1}</td>
     * </tr>
     * </table>
     *
     * @param alg the {@code SignatureAlgorithm} to inspect to determine which asymmetric algorithm to use.
     * @return a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.
     * @throws IllegalArgumentException if {@code alg} is not an asymmetric algorithm
     */
    public static KeyPair keyPairFor(SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        switch (alg) {
            case RS256:
            case PS256:
            case RS384:
            case PS384:
            case RS512:
            case PS512:
                return Classes.invokeStatic(RSA, "generateKeyPair", SIG_ARG_TYPES, alg);
            case ES256:
            case ES384:
            case ES512:
                return Classes.invokeStatic(EC, "generateKeyPair", SIG_ARG_TYPES, alg);
            default:
                String msg = "The " + alg.name() + " algorithm does not support Key Pairs.";
                throw new IllegalArgumentException(msg);
        }
    }
}

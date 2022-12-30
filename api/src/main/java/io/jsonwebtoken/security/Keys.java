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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;

/**
 * Utility class for securely generating {@link SecretKey}s and {@link KeyPair}s.
 *
 * @since 0.10.0
 */
public final class Keys {

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeysBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    @SuppressWarnings("rawtypes")
    private static final Class[] FOR_PASSWORD_ARG_TYPES = new Class[]{char[].class};

    //prevent instantiation
    private Keys() {
    }

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

        //Purposefully ordered higher to lower to ensure the strongest key possible can be generated.
        if (bitLength >= 512) {
            return new SecretKeySpec(bytes, "HmacSHA512");
        } else if (bitLength >= 384) {
            return new SecretKeySpec(bytes, "HmacSHA384");
        } else if (bitLength >= 256) {
            return new SecretKeySpec(bytes, "HmacSHA256");
        }

        String msg = "The specified key byte array is " + bitLength + " bits which " +
                "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " +
                "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " +
                "size >= 256 bits (the key size must be greater than or equal to the hash " +
                "output size).  Consider using the JwsAlgorithms.HS256.keyBuilder() method (or HS384.keyBuilder() " +
                "or HS512.keyBuilder()) to create a key guaranteed to be secure enough for your preferred HMAC-SHA " +
                "algorithm.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
        throw new WeakKeyException(msg);
    }

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>As of JJWT JJWT_RELEASE_VERSION, symmetric (secret) key algorithm instances can generate a key of suitable
     * length for that specific algorithm by calling their {@code keyBuilder()} method directly. For example:</p>
     *
     * <pre><code>
     * {@link JwsAlgorithms#HS256}.keyBuilder().build();
     * {@link JwsAlgorithms#HS384}.keyBuilder().build();
     * {@link JwsAlgorithms#HS512}.keyBuilder().build();
     * </code></pre>
     *
     * <p>Call those methods as needed instead of this static {@code secretKeyFor} helper method - the returned
     * {@link KeyBuilder} allows callers to specify a preferred Provider or SecureRandom on the builder if
     * desired, whereas this {@code secretKeyFor} method does not. Consequently this helper method will be removed
     * before the 1.0 release.</p>
     *
     * <p><b>Previous Documentation</b></p>
     *
     * <p>Returns a new {@link SecretKey} with a key length suitable for use with the specified {@link SignatureAlgorithm}.</p>
     *
     * <p><a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518), Section 3.2</a>
     * requires minimum key lengths to be used for each respective Signature Algorithm.  This method returns a
     * secure-random generated SecretKey that adheres to the required minimum key length.  The lengths are:</p>
     *
     * <table>
     *     <caption>JWA HMAC-SHA Key Length Requirements</caption>
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
     * @throws IllegalArgumentException for any input value other than {@link io.jsonwebtoken.SignatureAlgorithm#HS256},
     *                                  {@link io.jsonwebtoken.SignatureAlgorithm#HS384}, or {@link io.jsonwebtoken.SignatureAlgorithm#HS512}
     * @deprecated since JJWT_RELEASE_VERSION.  Use your preferred {@link MacAlgorithm} instance's
     * {@link MacAlgorithm#keyBuilder() keyBuilder()} method directly.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    public static SecretKey secretKeyFor(io.jsonwebtoken.SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        SecureDigestAlgorithm<?, ?> salg = JwsAlgorithms.forId(alg.name());
        if (!(salg instanceof MacAlgorithm)) {
            String msg = "The " + alg.name() + " algorithm does not support shared secret keys.";
            throw new IllegalArgumentException(msg);
        }
        return ((MacAlgorithm) salg).keyBuilder().build();
    }

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>As of JJWT JJWT_RELEASE_VERSION, asymmetric key algorithm instances can generate KeyPairs of suitable strength
     * for that specific algorithm by calling their {@code keyPairBuilder()} method directly. For example:</p>
     *
     * <pre><code>
     * {@link JwsAlgorithms#RS256}.keyPairBuilder().build();
     * {@link JwsAlgorithms#RS384}.keyPairBuilder().build();
     * {@link JwsAlgorithms#RS256}.keyPairBuilder().build();
     * ... etc ...
     * {@link JwsAlgorithms#ES512}.keyPairBuilder().build();
     * </code></pre>
     *
     * <p>Call those methods as needed instead of this static {@code keyPairFor} helper method - the returned
     * {@link KeyPairBuilder} allows callers to specify a preferred Provider or SecureRandom on the builder if
     * desired, whereas this {@code keyPairFor} method does not. Consequently this helper method will be removed
     * before the 1.0 release.</p>
     *
     * <p><b>Previous Documentation</b></p>
     *
     * <p>Returns a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.</p>
     *
     * <p>If the {@code alg} argument is an RSA algorithm, a KeyPair is generated based on the following:</p>
     *
     * <table>
     *     <caption>Generated RSA Key Sizes</caption>
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
     *     <caption>Generated Elliptic Curve Key Parameters</caption>
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
     * <td><b>521</b> bits</td>
     * <td>{@code P-521}</td>
     * <td>{@code secp521r1}</td>
     * </tr>
     * </table>
     *
     * @param alg the {@code SignatureAlgorithm} to inspect to determine which asymmetric algorithm to use.
     * @return a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.
     * @throws IllegalArgumentException if {@code alg} is not an asymmetric algorithm
     * @deprecated since JJWT_RELEASE_VERSION in favor of your preferred
     * {@link io.jsonwebtoken.security.SignatureAlgorithm} instance's
     * {@link SignatureAlgorithm#keyPairBuilder() keyPairBuilder()} method directly.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    public static KeyPair keyPairFor(io.jsonwebtoken.SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        SecureDigestAlgorithm<?, ?> salg = JwsAlgorithms.forId(alg.name());
        if (!(salg instanceof SignatureAlgorithm)) {
            String msg = "The " + alg.name() + " algorithm does not support Key Pairs.";
            throw new IllegalArgumentException(msg);
        }
        SignatureAlgorithm asalg = ((SignatureAlgorithm) salg);
        return asalg.keyPairBuilder().build();
    }

    /**
     * Returns a new {@link Password} instance suitable for use with password-based key derivation algorithms.
     *
     * <p><b>Usage Note</b>: Using {@code Password}s outside of key derivation contexts will likely
     * fail. See the {@link Password} JavaDoc for more, and also note the <b>Password Safety</b> section below.</p>
     *
     * <p><b>Password Safety</b></p>
     *
     * <p>Instances returned by this method use a <em>clone</em> of the specified {@code password} character array
     * argument - changes to the argument array will NOT be reflected in the returned key, and vice versa.  If you wish
     * to clear a {@code Password} instance to ensure it is no longer usable, call its {@link Password#destroy()}
     * method will clear/overwrite its internal cloned char array. Also note that each subsequent call to
     * {@link Password#toCharArray()} will also return a new clone of the underlying password character array per
     * standard JCE key behavior.</p>
     *
     * @param password the raw password character array to clone for use with password-based key derivation algorithms.
     * @return a new {@link Password} instance that wraps a new clone of the specified {@code password} character array.
     * @see Password#toCharArray()
     * @since JJWT_RELEASE_VERSION
     */
    public static Password forPassword(char[] password) {
        return Classes.invokeStatic(BRIDGE_CLASS, "forPassword", FOR_PASSWORD_ARG_TYPES, new Object[]{password});
    }
}

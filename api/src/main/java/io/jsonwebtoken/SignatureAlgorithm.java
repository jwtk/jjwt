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
package io.jsonwebtoken;

import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Type-safe representation of standard JWT signature algorithm names as defined in the
 * <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31">JSON Web Algorithms</a> specification.
 *
 * @since 0.1
 */
public enum SignatureAlgorithm {

    /**
     * JWA name for {@code No digital signature or MAC performed}
     */
    NONE("none", "No digital signature or MAC performed", "None", null, false, 0, 0),

    /**
     * JWA algorithm name for {@code HMAC using SHA-256}
     */
    HS256("HS256", "HMAC using SHA-256", "HMAC", "HmacSHA256", true, 256, 256, "1.2.840.113549.2.9"),

    /**
     * JWA algorithm name for {@code HMAC using SHA-384}
     */
    HS384("HS384", "HMAC using SHA-384", "HMAC", "HmacSHA384", true, 384, 384, "1.2.840.113549.2.10"),

    /**
     * JWA algorithm name for {@code HMAC using SHA-512}
     */
    HS512("HS512", "HMAC using SHA-512", "HMAC", "HmacSHA512", true, 512, 512, "1.2.840.113549.2.11"),

    /**
     * JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-256}
     */
    RS256("RS256", "RSASSA-PKCS-v1_5 using SHA-256", "RSA", "SHA256withRSA", true, 256, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-384}
     */
    RS384("RS384", "RSASSA-PKCS-v1_5 using SHA-384", "RSA", "SHA384withRSA", true, 384, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-512}
     */
    RS512("RS512", "RSASSA-PKCS-v1_5 using SHA-512", "RSA", "SHA512withRSA", true, 512, 2048),

    /**
     * JWA algorithm name for {@code ECDSA using P-256 and SHA-256}
     */
    ES256("ES256", "ECDSA using P-256 and SHA-256", "ECDSA", "SHA256withECDSA", true, 256, 256),

    /**
     * JWA algorithm name for {@code ECDSA using P-384 and SHA-384}
     */
    ES384("ES384", "ECDSA using P-384 and SHA-384", "ECDSA", "SHA384withECDSA", true, 384, 384),

    /**
     * JWA algorithm name for {@code ECDSA using P-521 and SHA-512}
     */
    ES512("ES512", "ECDSA using P-521 and SHA-512", "ECDSA", "SHA512withECDSA", true, 512, 521),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256}.  <b>This algorithm requires
     * Java 11 or later or a JCA provider like BouncyCastle to be in the runtime classpath.</b>  If on Java 10 or
     * earlier, BouncyCastle will be used automatically if found in the runtime classpath.
     */
    PS256("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "RSA", "RSASSA-PSS", false, 256, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384}.  <b>This algorithm requires
     * Java 11 or later or a JCA provider like BouncyCastle to be in the runtime classpath.</b>  If on Java 10 or
     * earlier, BouncyCastle will be used automatically if found in the runtime classpath.
     */
    PS384("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "RSA", "RSASSA-PSS", false, 384, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512}. <b>This algorithm requires
     * Java 11 or later or a JCA provider like BouncyCastle to be in the runtime classpath.</b>  If on Java 10 or
     * earlier, BouncyCastle will be used automatically if found in the runtime classpath.
     */
    PS512("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "RSA", "RSASSA-PSS", false, 512, 2048);

    //purposefully ordered higher to lower:
    private static final List<SignatureAlgorithm> PREFERRED_HMAC_ALGS = Collections.unmodifiableList(Arrays.asList(
        SignatureAlgorithm.HS512, SignatureAlgorithm.HS384, SignatureAlgorithm.HS256));
    //purposefully ordered higher to lower:
    private static final List<SignatureAlgorithm> PREFERRED_EC_ALGS = Collections.unmodifiableList(Arrays.asList(
        SignatureAlgorithm.ES512, SignatureAlgorithm.ES384, SignatureAlgorithm.ES256));

    private final String value;
    private final String description;
    private final String familyName;
    private final String jcaName;
    private final boolean jdkStandard;
    private final int digestLength;
    private final int minKeyLength;
    /**
     * Algorithm name as given by {@link Key#getAlgorithm()} if the key was loaded from a pkcs12 Keystore.
     *
     * @deprecated This is just a workaround for https://bugs.openjdk.java.net/browse/JDK-8243551
     */
    @Deprecated
    private final String pkcs12Name;

    SignatureAlgorithm(String value, String description, String familyName, String jcaName, boolean jdkStandard,
                       int digestLength, int minKeyLength) {
        this(value, description,familyName, jcaName, jdkStandard, digestLength, minKeyLength, jcaName);
    }

    SignatureAlgorithm(String value, String description, String familyName, String jcaName, boolean jdkStandard,
                       int digestLength, int minKeyLength, String pkcs12Name) {
        this.value = value;
        this.description = description;
        this.familyName = familyName;
        this.jcaName = jcaName;
        this.jdkStandard = jdkStandard;
        this.digestLength = digestLength;
        this.minKeyLength = minKeyLength;
        this.pkcs12Name = pkcs12Name;
    }

    /**
     * Returns the JWA algorithm name constant.
     *
     * @return the JWA algorithm name constant.
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns the JWA algorithm description.
     *
     * @return the JWA algorithm description.
     */
    public String getDescription() {
        return description;
    }


    /**
     * Returns the cryptographic family name of the signature algorithm.  The value returned is according to the
     * following table:
     *
     * <table>
     * <caption>Crypto Family</caption>
     * <thead>
     * <tr>
     * <th>SignatureAlgorithm</th>
     * <th>Family Name</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td>HS256</td>
     * <td>HMAC</td>
     * </tr>
     * <tr>
     * <td>HS384</td>
     * <td>HMAC</td>
     * </tr>
     * <tr>
     * <td>HS512</td>
     * <td>HMAC</td>
     * </tr>
     * <tr>
     * <td>RS256</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>RS384</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>RS512</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>PS256</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>PS384</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>PS512</td>
     * <td>RSA</td>
     * </tr>
     * <tr>
     * <td>ES256</td>
     * <td>ECDSA</td>
     * </tr>
     * <tr>
     * <td>ES384</td>
     * <td>ECDSA</td>
     * </tr>
     * <tr>
     * <td>ES512</td>
     * <td>ECDSA</td>
     * </tr>
     * </tbody>
     * </table>
     *
     * @return Returns the cryptographic family name of the signature algorithm.
     * @since 0.5
     */
    public String getFamilyName() {
        return familyName;
    }

    /**
     * Returns the name of the JCA algorithm used to compute the signature.
     *
     * @return the name of the JCA algorithm used to compute the signature.
     */
    public String getJcaName() {
        return jcaName;
    }

    /**
     * Returns {@code true} if the algorithm is supported by standard JDK distributions or {@code false} if the
     * algorithm implementation is not in the JDK and must be provided by a separate runtime JCA Provider (like
     * BouncyCastle for example).
     *
     * @return {@code true} if the algorithm is supported by standard JDK distributions or {@code false} if the
     * algorithm implementation is not in the JDK and must be provided by a separate runtime JCA Provider (like
     * BouncyCastle for example).
     */
    public boolean isJdkStandard() {
        return jdkStandard;
    }

    /**
     * Returns {@code true} if the enum instance represents an HMAC signature algorithm, {@code false} otherwise.
     *
     * @return {@code true} if the enum instance represents an HMAC signature algorithm, {@code false} otherwise.
     */
    public boolean isHmac() {
        return familyName.equals("HMAC");
    }

    /**
     * Returns {@code true} if the enum instance represents an RSA public/private key pair signature algorithm,
     * {@code false} otherwise.
     *
     * @return {@code true} if the enum instance represents an RSA public/private key pair signature algorithm,
     * {@code false} otherwise.
     */
    public boolean isRsa() {
        return familyName.equals("RSA");
    }

    /**
     * Returns {@code true} if the enum instance represents an Elliptic Curve ECDSA signature algorithm, {@code false}
     * otherwise.
     *
     * @return {@code true} if the enum instance represents an Elliptic Curve ECDSA signature algorithm, {@code false}
     * otherwise.
     */
    public boolean isEllipticCurve() {
        return familyName.equals("ECDSA");
    }

    /**
     * Returns the minimum key length in bits (not bytes) that may be used with this algorithm according to the
     * <a href="https://tools.ietf.org/html/rfc7518">JWT JWA Specification (RFC 7518)</a>.
     *
     * @return the minimum key length in bits (not bytes) that may be used with this algorithm according to the
     * <a href="https://tools.ietf.org/html/rfc7518">JWT JWA Specification (RFC 7518)</a>.
     * @since 0.10.0
     */
    public int getMinKeyLength() {
        return this.minKeyLength;
    }

    /**
     * Returns quietly if the specified key is allowed to create signatures using this algorithm
     * according to the <a href="https://tools.ietf.org/html/rfc7518">JWT JWA Specification (RFC 7518)</a> or throws an
     * {@link InvalidKeyException} if the key is not allowed or not secure enough for this algorithm.
     *
     * @param key the key to check for validity.
     * @throws InvalidKeyException if the key is not allowed or not secure enough for this algorithm.
     * @since 0.10.0
     */
    public void assertValidSigningKey(Key key) throws InvalidKeyException {
        assertValid(key, true);
    }

    /**
     * Returns quietly if the specified key is allowed to verify signatures using this algorithm
     * according to the <a href="https://tools.ietf.org/html/rfc7518">JWT JWA Specification (RFC 7518)</a> or throws an
     * {@link InvalidKeyException} if the key is not allowed or not secure enough for this algorithm.
     *
     * @param key the key to check for validity.
     * @throws InvalidKeyException if the key is not allowed or not secure enough for this algorithm.
     * @since 0.10.0
     */
    public void assertValidVerificationKey(Key key) throws InvalidKeyException {
        assertValid(key, false);
    }

    /**
     * @since 0.10.0 to support assertValid(Key, boolean)
     */
    private static String keyType(boolean signing) {
        return signing ? "signing" : "verification";
    }

    /**
     * @since 0.10.0
     */
    private void assertValid(Key key, boolean signing) throws InvalidKeyException {

        if (this == NONE) {

            String msg = "The 'NONE' signature algorithm does not support cryptographic keys.";
            throw new InvalidKeyException(msg);

        } else if (isHmac()) {

            if (!(key instanceof SecretKey)) {
                String msg = this.familyName + " " + keyType(signing) + " keys must be SecretKey instances.";
                throw new InvalidKeyException(msg);
            }
            SecretKey secretKey = (SecretKey) key;

            byte[] encoded = secretKey.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("The " + keyType(signing) + " key's encoded bytes cannot be null.");
            }

            String alg = secretKey.getAlgorithm();
            if (alg == null) {
                throw new InvalidKeyException("The " + keyType(signing) + " key's algorithm cannot be null.");
            }

            // These next checks use equalsIgnoreCase per https://github.com/jwtk/jjwt/issues/381#issuecomment-412912272
            if (!HS256.jcaName.equalsIgnoreCase(alg) &&
                !HS384.jcaName.equalsIgnoreCase(alg) &&
                !HS512.jcaName.equalsIgnoreCase(alg) &&
                !HS256.pkcs12Name.equals(alg) &&
                !HS384.pkcs12Name.equals(alg) &&
                !HS512.pkcs12Name.equals(alg)) {
                throw new InvalidKeyException("The " + keyType(signing) + " key's algorithm '" + alg +
                    "' does not equal a valid HmacSHA* algorithm name and cannot be used with " + name() + ".");
            }

            int size = encoded.length * 8; //size in bits
            if (size < this.minKeyLength) {
                String msg = "The " + keyType(signing) + " key's size is " + size + " bits which " +
                    "is not secure enough for the " + name() + " algorithm.  The JWT " +
                    "JWA Specification (RFC 7518, Section 3.2) states that keys used with " + name() + " MUST have a " +
                    "size >= " + minKeyLength + " bits (the key size must be greater than or equal to the hash " +
                    "output size).  Consider using the " + Keys.class.getName() + " class's " +
                    "'secretKeyFor(SignatureAlgorithm." + name() + ")' method to create a key guaranteed to be " +
                    "secure enough for " + name() + ".  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
                throw new WeakKeyException(msg);
            }

        } else { //EC or RSA

            if (signing) {
                if (!(key instanceof PrivateKey)) {
                    String msg = familyName + " signing keys must be PrivateKey instances.";
                    throw new InvalidKeyException(msg);
                }
            }

            if (isEllipticCurve()) {

                if (!(key instanceof ECKey)) {
                    String msg = familyName + " " + keyType(signing) + " keys must be ECKey instances.";
                    throw new InvalidKeyException(msg);
                }

                ECKey ecKey = (ECKey) key;
                int size = ecKey.getParams().getOrder().bitLength();
                if (size < this.minKeyLength) {
                    String msg = "The " + keyType(signing) + " key's size (ECParameterSpec order) is " + size +
                        " bits which is not secure enough for the " + name() + " algorithm.  The JWT " +
                        "JWA Specification (RFC 7518, Section 3.4) states that keys used with " +
                        name() + " MUST have a size >= " + this.minKeyLength +
                        " bits.  Consider using the " + Keys.class.getName() + " class's " +
                        "'keyPairFor(SignatureAlgorithm." + name() + ")' method to create a key pair guaranteed " +
                        "to be secure enough for " + name() + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.4 for more information.";
                    throw new WeakKeyException(msg);
                }

            } else { //RSA

                if (!(key instanceof RSAKey)) {
                    String msg = familyName + " " + keyType(signing) + " keys must be RSAKey instances.";
                    throw new InvalidKeyException(msg);
                }

                RSAKey rsaKey = (RSAKey) key;
                int size = rsaKey.getModulus().bitLength();
                if (size < this.minKeyLength) {

                    String section = name().startsWith("P") ? "3.5" : "3.3";

                    String msg = "The " + keyType(signing) + " key's size is " + size + " bits which is not secure " +
                        "enough for the " + name() + " algorithm.  The JWT JWA Specification (RFC 7518, Section " +
                        section + ") states that keys used with " + name() + " MUST have a size >= " +
                        this.minKeyLength + " bits.  Consider using the " + Keys.class.getName() + " class's " +
                        "'keyPairFor(SignatureAlgorithm." + name() + ")' method to create a key pair guaranteed " +
                        "to be secure enough for " + name() + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-" + section + " for more information.";
                    throw new WeakKeyException(msg);
                }
            }
        }
    }

    /**
     * Returns the recommended signature algorithm to be used with the specified key according to the following
     * heuristics:
     *
     * <table>
     * <caption>Key Signature Algorithm</caption>
     * <thead>
     * <tr>
     * <th>If the Key is a:</th>
     * <th>And:</th>
     * <th>With a key size of:</th>
     * <th>The returned SignatureAlgorithm will be:</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA256")</code><sup>1</sup></td>
     * <td>256 &lt;= size &lt;= 383 <sup>2</sup></td>
     * <td>{@link SignatureAlgorithm#HS256 HS256}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA384")</code><sup>1</sup></td>
     * <td>384 &lt;= size &lt;= 511</td>
     * <td>{@link SignatureAlgorithm#HS384 HS384}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA512")</code><sup>1</sup></td>
     * <td>512 &lt;= size</td>
     * <td>{@link SignatureAlgorithm#HS512 HS512}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>256 &lt;= size &lt;= 383 <sup>3</sup></td>
     * <td>{@link SignatureAlgorithm#ES256 ES256}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>384 &lt;= size &lt;= 511</td>
     * <td>{@link SignatureAlgorithm#ES384 ES384}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>4096 &lt;= size</td>
     * <td>{@link SignatureAlgorithm#ES512 ES512}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>2048 &lt;= size &lt;= 3071 <sup>4,5</sup></td>
     * <td>{@link SignatureAlgorithm#RS256 RS256}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>3072 &lt;= size &lt;= 4095 <sup>5</sup></td>
     * <td>{@link SignatureAlgorithm#RS384 RS384}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>4096 &lt;= size <sup>5</sup></td>
     * <td>{@link SignatureAlgorithm#RS512 RS512}</td>
     * </tr>
     * </tbody>
     * </table>
     * <p>Notes:</p>
     * <ol>
     * <li>{@code SecretKey} instances must have an {@link Key#getAlgorithm() algorithm} name equal
     * to {@code HmacSHA256}, {@code HmacSHA384} or {@code HmacSHA512}.  If not, the key bytes might not be
     * suitable for HMAC signatures will be rejected with a {@link InvalidKeyException}. </li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518,
     * Section 3.2)</a> mandates that HMAC-SHA-* signing keys <em>MUST</em> be 256 bits or greater.
     * {@code SecretKey}s with key lengths less than 256 bits will be rejected with an
     * {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.4">JWA Specification (RFC 7518,
     * Section 3.4)</a> mandates that ECDSA signing key lengths <em>MUST</em> be 256 bits or greater.
     * {@code ECKey}s with key lengths less than 256 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.3">JWA Specification (RFC 7518,
     * Section 3.3)</a> mandates that RSA signing key lengths <em>MUST</em> be 2048 bits or greater.
     * {@code RSAKey}s with key lengths less than 2048 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>Technically any RSA key of length >= 2048 bits may be used with the {@link #RS256}, {@link #RS384}, and
     * {@link #RS512} algorithms, so we assume an RSA signature algorithm based on the key length to
     * parallel similar decisions in the JWT specification for HMAC and ECDSA signature algorithms.
     * This is not required - just a convenience.</li>
     * </ol>
     * <p>This implementation does not return the {@link #PS256}, {@link #PS256}, {@link #PS256} RSA variant for any
     * specified {@link RSAKey} because:
     * <ul>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.1">JWA Specification (RFC 7518,
     * Section 3.1)</a> indicates that {@link #RS256}, {@link #RS384}, and {@link #RS512} are
     * recommended algorithms while the {@code PS}* variants are simply marked as optional.</li>
     * <li>The {@link #RS256}, {@link #RS384}, and {@link #RS512} algorithms are available in the JDK by default
     * while the {@code PS}* variants require an additional JCA Provider (like BouncyCastle).</li>
     * </ul>
     * </p>
     *
     * <p>Finally, this method will throw an {@link InvalidKeyException} for any key that does not match the
     * heuristics and requirements documented above, since that inevitably means the Key is either insufficient or
     * explicitly disallowed by the JWT specification.</p>
     *
     * @param key the key to inspect
     * @return the recommended signature algorithm to be used with the specified key
     * @throws InvalidKeyException for any key that does not match the heuristics and requirements documented above,
     *                             since that inevitably means the Key is either insufficient or explicitly disallowed by the JWT specification.
     * @since 0.10.0
     */
    public static SignatureAlgorithm forSigningKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key argument cannot be null.");
        }

        if (!(key instanceof SecretKey ||
            (key instanceof PrivateKey && (key instanceof ECKey || key instanceof RSAKey)))) {
            String msg = "JWT standard signing algorithms require either 1) a SecretKey for HMAC-SHA algorithms or " +
                "2) a private RSAKey for RSA algorithms or 3) a private ECKey for Elliptic Curve algorithms.  " +
                "The specified key is of type " + key.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        if (key instanceof SecretKey) {

            SecretKey secretKey = (SecretKey)key;
            int bitLength = io.jsonwebtoken.lang.Arrays.length(secretKey.getEncoded()) * Byte.SIZE;

            for(SignatureAlgorithm alg : PREFERRED_HMAC_ALGS) {
                // ensure compatibility check is based on key length. See https://github.com/jwtk/jjwt/issues/381
                if (bitLength >= alg.minKeyLength) {
                    return alg;
                }
            }

            String msg = "The specified SecretKey is not strong enough to be used with JWT HMAC signature " +
                "algorithms.  The JWT specification requires HMAC keys to be >= 256 bits long.  The specified " +
                "key is " + bitLength + " bits.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more " +
                "information.";
            throw new WeakKeyException(msg);
        }

        if (key instanceof RSAKey) {

            RSAKey rsaKey = (RSAKey) key;
            int bitLength = rsaKey.getModulus().bitLength();

            if (bitLength >= 4096) {
                RS512.assertValidSigningKey(key);
                return RS512;
            } else if (bitLength >= 3072) {
                RS384.assertValidSigningKey(key);
                return RS384;
            } else if (bitLength >= RS256.minKeyLength) {
                RS256.assertValidSigningKey(key);
                return RS256;
            }

            String msg = "The specified RSA signing key is not strong enough to be used with JWT RSA signature " +
                "algorithms.  The JWT specification requires RSA keys to be >= 2048 bits long.  The specified RSA " +
                "key is " + bitLength + " bits.  See https://tools.ietf.org/html/rfc7518#section-3.3 for more " +
                "information.";
            throw new WeakKeyException(msg);
        }

        // if we've made it this far in the method, the key is an ECKey due to the instanceof assertions at the
        // top of the method

        ECKey ecKey = (ECKey) key;
        int bitLength = ecKey.getParams().getOrder().bitLength();

        for (SignatureAlgorithm alg : PREFERRED_EC_ALGS) {
            if (bitLength >= alg.minKeyLength) {
                alg.assertValidSigningKey(key);
                return alg;
            }
        }

        String msg = "The specified Elliptic Curve signing key is not strong enough to be used with JWT ECDSA " +
            "signature algorithms.  The JWT specification requires ECDSA keys to be >= 256 bits long.  " +
            "The specified ECDSA key is " + bitLength + " bits.  See " +
            "https://tools.ietf.org/html/rfc7518#section-3.4 for more information.";
        throw new WeakKeyException(msg);
    }

    /**
     * Looks up and returns the corresponding {@code SignatureAlgorithm} enum instance based on a
     * case-<em>insensitive</em> name comparison.
     *
     * @param value The case-insensitive name of the {@code SignatureAlgorithm} instance to return
     * @return the corresponding {@code SignatureAlgorithm} enum instance based on a
     * case-<em>insensitive</em> name comparison.
     * @throws SignatureException if the specified value does not match any {@code SignatureAlgorithm}
     *                            name.
     */
    public static SignatureAlgorithm forName(String value) throws SignatureException {
        for (SignatureAlgorithm alg : values()) {
            if (alg.getValue().equalsIgnoreCase(value)) {
                return alg;
            }
        }

        throw new SignatureException("Unsupported signature algorithm '" + value + "'");
    }
}

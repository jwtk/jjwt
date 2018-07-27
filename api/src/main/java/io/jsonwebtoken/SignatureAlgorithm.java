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

import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

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
    HS256("HS256", "HMAC using SHA-256", "HMAC", "HmacSHA256", true, 256, 256),

    /**
     * JWA algorithm name for {@code HMAC using SHA-384}
     */
    HS384("HS384", "HMAC using SHA-384", "HMAC", "HmacSHA384", true, 384, 384),

    /**
     * JWA algorithm name for {@code HMAC using SHA-512}
     */
    HS512("HS512", "HMAC using SHA-512", "HMAC", "HmacSHA512", true, 512, 512),

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
     * JWA algorithm name for {@code ECDSA using P-256 and SHA-256}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES256("ES256", "ECDSA using P-256 and SHA-256", "ECDSA", "SHA256withECDSA", false, 256, 256),

    /**
     * JWA algorithm name for {@code ECDSA using P-384 and SHA-384}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES384("ES384", "ECDSA using P-384 and SHA-384", "ECDSA", "SHA384withECDSA", false, 384, 384),

    /**
     * JWA algorithm name for {@code ECDSA using P-521 and SHA-512}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES512("ES512", "ECDSA using P-521 and SHA-512", "ECDSA", "SHA512withECDSA", false, 512, 521),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256}.  <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle
     * will be used automatically if found in the runtime classpath.
     */
    PS256("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "RSA", "SHA256withRSAandMGF1", false, 256, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384}.  <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle
     * will be used automatically if found in the runtime classpath.
     */
    PS384("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "RSA", "SHA384withRSAandMGF1", false, 384, 2048),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512}. <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    PS512("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "RSA", "SHA512withRSAandMGF1", false, 512, 2048);

    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible();
    }

    private final String value;
    private final String description;
    private final String familyName;
    private final String jcaName;
    private final boolean jdkStandard;
    private final int digestLength;
    private final int minKeyLength;

    SignatureAlgorithm(String value, String description, String familyName, String jcaName, boolean jdkStandard,
                       int digestLength, int minKeyLength) {
        this.value = value;
        this.description = description;
        this.familyName = familyName;
        this.jcaName = jcaName;
        this.jdkStandard = jdkStandard;
        this.digestLength = digestLength;
        this.minKeyLength = minKeyLength;
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
            if (!HS256.jcaName.equals(alg) && !HS384.jcaName.equals(alg) && !HS512.jcaName.equals(alg)) {
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

                RSAKey rsaKey = (RSAKey)key;
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

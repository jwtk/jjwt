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

/**
 * Type-safe representation of standard JWT signature algorithm names as defined in the
 * <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31">JSON Web Algorithms</a> specification.
 *
 * @since 0.1
 */
public enum SignatureAlgorithm {

    /** JWA name for {@code No digital signature or MAC performed} */
    NONE("none", "No digital signature or MAC performed", null, false),

    /** JWA algorithm name for {@code HMAC using SHA-256} */
    HS256("HS256", "HMAC using SHA-256", "HmacSHA256", true),

    /** JWA algorithm name for {@code HMAC using SHA-384} */
    HS384("HS384", "HMAC using SHA-384", "HmacSHA384", true),

    /** JWA algorithm name for {@code HMAC using SHA-512} */
    HS512("HS512", "HMAC using SHA-512", "HmacSHA512", true),

    /** JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-256} */
    RS256("RS256", "RSASSA-PKCS-v1_5 using SHA-256", "SHA256withRSA", true),

    /** JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-384} */
    RS384("RS384", "RSASSA-PKCS-v1_5 using SHA-384", "SHA384withRSA", true),

    /** JWA algorithm name for {@code RSASSA-PKCS-v1_5 using SHA-512} */
    RS512("RS512", "RSASSA-PKCS-v1_5 using SHA-512", "SHA512withRSA", true),

    /**
     * JWA algorithm name for {@code ECDSA using P-256 and SHA-256}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES256("ES256", "ECDSA using P-256 and SHA-256", "secp256r1", false),

    /**
     * JWA algorithm name for {@code ECDSA using P-384 and SHA-384}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES384("ES384", "ECDSA using P-384 and SHA-384", "secp384r1", false),

    /**
     * JWA algorithm name for {@code ECDSA using P-512 and SHA-512}.  <b>This is not a JDK standard algorithm and
     * requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    ES512("ES512", "ECDSA using P-512 and SHA-512", "secp521r1", false),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256}.  <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle
     * will be used automatically if found in the runtime classpath.
     */
    PS256("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "SHA256withRSAandMGF1", false),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384}.  <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the runtime classpath.</b>  BouncyCastle
     * will be used automatically if found in the runtime classpath.
     */
    PS384("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "SHA384withRSAandMGF1", false),

    /**
     * JWA algorithm name for {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512}. <b>This is not a JDK standard
     * algorithm and requires that a JCA provider like BouncyCastle be in the classpath.</b>  BouncyCastle will be used
     * automatically if found in the runtime classpath.
     */
    PS512("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "SHA512withRSAandMGF1", false);

    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible();
    }

    private final String  value;
    private final String  description;
    private final String  jcaName;
    private final boolean jdkStandard;

    private SignatureAlgorithm(String value, String description, String jcaName, boolean jdkStandard) {
        this.value = value;
        this.description = description;
        this.jcaName = jcaName;
        this.jdkStandard = jdkStandard;
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
        return name().startsWith("HS");
    }

    /**
     * Returns {@code true} if the enum instance represents an RSA public/private key pair signature algorithm,
     * {@code false} otherwise.
     *
     * @return {@code true} if the enum instance represents an RSA public/private key pair signature algorithm,
     * {@code false} otherwise.
     */
    public boolean isRsa() {
        return getDescription().startsWith("RSASSA");
    }

    /**
     * Returns {@code true} if the enum instance represents an Elliptic Curve signature algorithm, {@code false}
     * otherwise.
     *
     * @return {@code true} if the enum instance represents an Elliptic Curve signature algorithm, {@code false}
     * otherwise.
     */
    public boolean isEllipticCurve() {
        return name().startsWith("ES");
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

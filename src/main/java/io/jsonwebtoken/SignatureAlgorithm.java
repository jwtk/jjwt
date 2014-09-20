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
 * Type-safe representation of standard JWT algorithm names as defined in the
 * <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31">JSON Web Algorithms</a> specification.
 *
 * @since 0.1
 */
public enum SignatureAlgorithm {

    NONE("none", "No digital signature or MAC performed", null, false),
    HS256("HS256", "HMAC using SHA-256", "HmacSHA256", true),
    HS384("HS384", "HMAC using SHA-384", "HmacSHA384", true),
    HS512("HS512", "HMAC using SHA-512", "HmacSHA512", true),
    RS256("RS256", "RSASSA-PKCS-v1_5 using SHA-256", "SHA256withRSA", true),
    RS384("RS384", "RSASSA-PKCS-v1_5 using SHA-384", "SHA384withRSA", true),
    RS512("RS512", "RSASSA-PKCS-v1_5 using SHA-512", "SHA512withRSA", true),
    ES256("ES256", "ECDSA using P-256 and SHA-256", "secp256r1", false), //bouncy castle, not in the jdk
    ES384("ES384", "ECDSA using P-384 and SHA-384", "secp384r1", false), //bouncy castle, not in the jdk
    ES512("ES512", "ECDSA using P-512 and SHA-512", "secp521r1", false), //bouncy castle, not in the jdk
    PS256("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "SHA256withRSAandMGF1", false), //bouncy castle, not in the jdk
    PS384("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "SHA384withRSAandMGF1", false), //bouncy castle, not in the jdk
    PS512("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "SHA512withRSAandMGF1", false); //bouncy castle, not in the jdk

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

    public String getValue() {
        return value;
    }

    public String getDescription() {
        return description;
    }

    public String getJcaName() {
        return jcaName;
    }

    public boolean isJdkStandard() {
        return jdkStandard;
    }

    public boolean isHmac() {
        return name().startsWith("HS");
    }

    public boolean isRsa() {
        return getDescription().startsWith("RSASSA");
    }

    public boolean isEllipticCurve() {
        return name().startsWith("ES");
    }

    public static SignatureAlgorithm forName(String value) {
        for (SignatureAlgorithm alg : values()) {
            if (alg.getValue().equalsIgnoreCase(value)) {
                return alg;
            }
        }

        throw new SignatureException("Unsupported signature algorithm '" + value + "'");
    }
}

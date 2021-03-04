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

/**
 * A <a href="https://tools.ietf.org/html/rfc7515">JWS</a> header.
 *
 * @since 0.1
 */
public interface JwsHeader extends Header<JwsHeader> {

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">Algorithm Header</a> name: the string literal <b><code>alg</code></b>
     */
    public static final String ALGORITHM = "alg";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.2">JWK Set URL Header</a> name: the string literal <b><code>jku</code></b>
     */
    public static final String JWK_SET_URL = "jku";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.3">JSON Web Key Header</a> name: the string literal <b><code>jwk</code></b>
     */
    public static final String JSON_WEB_KEY = "jwk";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">Key ID Header</a> name: the string literal <b><code>kid</code></b>
     */
    public static final String KEY_ID = "kid";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.5">X.509 URL Header</a> name: the string literal <b><code>x5u</code></b>
     */
    public static final String X509_URL = "x5u";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.6">X.509 Certificate Chain Header</a> name: the string literal <b><code>x5c</code></b>
     */
    public static final String X509_CERT_CHAIN = "x5c";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.7">X.509 Certificate SHA-1 Thumbprint Header</a> name: the string literal <b><code>x5t</code></b>
     */
    public static final String X509_CERT_SHA1_THUMBPRINT = "x5t";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.8">X.509 Certificate SHA-256 Thumbprint Header</a> name: the string literal <b><code>x5t#S256</code></b>
     */
    public static final String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.11">Critical Header</a> name: the string literal <b><code>crit</code></b>
     */
    public static final String CRITICAL = "crit";

    /**
     * Returns the JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">
     * <code>kid</code></a> (Key ID) header value or {@code null} if not present.
     * <p>The keyId header parameter is a hint indicating which key was used to secure the JWS.  This parameter allows
     * originators to explicitly signal a change of key to recipients.  The structure of the keyId value is
     * unspecified.</p>
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @return the JWS {@code kid} header value or {@code null} if not present.
     */
    String getKeyId();

    /**
     * Sets the JWT <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">
     * <code>kid</code></a> (Key ID) header value.  A {@code null} value will remove the property from the JSON map.
     * <p>The keyId header parameter is a hint indicating which key was used to secure the JWS.  This parameter allows
     * originators to explicitly signal a change of key to recipients.  The structure of the keyId value is
     * unspecified.</p>
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @param kid the JWS {@code kid} header value or {@code null} to remove the property from the JSON map.
     * @return the {@code Header} instance for method chaining.
     */
    JwsHeader setKeyId(String kid);
}

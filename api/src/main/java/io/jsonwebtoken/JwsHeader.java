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
public interface JwsHeader extends ProtectedHeader {

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">Algorithm Header</a> name: the string literal <b><code>alg</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getAlgorithm()}
     */
    @Deprecated
    String ALGORITHM = "alg";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.2">JWK Set URL Header</a> name: the string literal <b><code>jku</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getJwkSetUrl()}
     */
    @Deprecated
    String JWK_SET_URL = "jku";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7515#section-4.1.3">JSON Web Key Header</a> name: the string literal <b><code>jwk</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getJwk()}
     */
    @Deprecated
    String JSON_WEB_KEY = "jwk";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">Key ID Header</a> name: the string literal <b><code>kid</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getKeyId()}
     */
    @Deprecated
    String KEY_ID = "kid";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.5">X.509 URL Header</a> name: the string literal <b><code>x5u</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getX509Url()}
     */
    @Deprecated
    String X509_URL = "x5u";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.6">X.509 Certificate Chain Header</a> name: the string literal <b><code>x5c</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getX509CertificateChain()}
     */
    @Deprecated
    String X509_CERT_CHAIN = "x5c";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.7">X.509 Certificate SHA-1 Thumbprint Header</a> name: the string literal <b><code>x5t</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getX509CertificateSha1Thumbprint()}
     */
    @Deprecated
    String X509_CERT_SHA1_THUMBPRINT = "x5t";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.8">X.509 Certificate SHA-256 Thumbprint Header</a> name: the string literal <b><code>x5t#S256</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getX509CertificateSha256Thumbprint()}
     */
    @Deprecated
    String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

    /**
     * JWS <a href="https://tools.ietf.org/html/rfc7516#section-4.1.11">Critical Header</a> name: the string literal <b><code>crit</code></b>
     *
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getCritical()}
     */
    @Deprecated
    String CRITICAL = "crit";
}

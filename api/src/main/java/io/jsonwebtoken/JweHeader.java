/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * A <a href="https://tools.ietf.org/html/rfc7516">JWE</a> header.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JweHeader extends Header<JweHeader> {

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">Algorithm Header</a> name: the string literal <b><code>alg</code></b>
     */
    String ALGORITHM = "alg";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2">Encryption Algorithm Header</a> name: the string literal <b><code>enc</code></b>
     */
    String ENCRYPTION_ALGORITHM = "enc";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3">Compression Algorithm Header</a> name: the string literal <b><code>zip</code></b>
     */
    String COMPRESSION_ALGORITHM = "zip";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.4">JWK Set URL Header</a> name: the string literal <b><code>jku</code></b>
     */
    String JWK_SET_URL = "jku";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.5">JSON Web Key Header</a> name: the string literal <b><code>jwk</code></b>
     */
    String JSON_WEB_KEY = "jwk";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.6">Key ID Header</a> name: the string literal <b><code>kid</code></b>
     */
    String KEY_ID = "kid";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.7">X.509 URL Header</a> name: the string literal <b><code>x5u</code></b>
     */
    String X509_URL = "x5u";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.8">X.509 Certificate Chain Header</a> name: the string literal <b><code>x5c</code></b>
     */
    String X509_CERT_CHAIN = "x5c";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.9">X.509 Certificate SHA-1 Thumbprint Header</a> name: the string literal <b><code>x5t</code></b>
     */
    String X509_CERT_SHA1_THUMBPRINT = "x5t";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.10">X.509 Certificate SHA-256 Thumbprint Header</a> name: the string literal <b><code>x5t#S256</code></b>
     */
    String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

    /**
     * JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.13">Critical Header</a> name: the string literal <b><code>crit</code></b>
     */
    String CRITICAL = "crit";

    /**
     * Returns the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2"><code>enc</code></a> (Encryption
     * Algorithm) header value or {@code null} if not present.
     * <p>The JWE {@code enc} (encryption algorithm) Header Parameter identifies the content encryption algorithm
     * used to perform authenticated encryption on the plaintext to produce the ciphertext and the JWE
     * {@code Authentication Tag}.</p>
     *
     * @return the JWE {@code enc} (Encryption Algorithm) header value or {@code null} if not present.  This will
     * always be {@code non-null} on validly constructed JWE instances, but could be {@code null} during construction.
     */
    String getEncryptionAlgorithm();

    //commented out on purpose - API users shouldn't call this method as it is always called by the Jwt/Jwe Builder
//    /**
//     * Sets the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2"><code>enc</code></a> (Encryption
//     * Algorithm) header value.  A {@code null} value will remove the property from the JSON map.
//     * <p>The JWE {@code enc} (encryption algorithm) Header Parameter identifies the content encryption algorithm
//     * used to perform authenticated encryption on the plaintext to produce the ciphertext and the JWE
//     * {@code Authentication Tag}.</p>
//     *
//     * @param enc the encryption algorithm identifier
//     * @return this header for method chaining
//     */
//    JweHeader setEncryptionAlgorithm(String enc);

    URI getJwkSetUrl();
    JweHeader setJwkSetUrl(URI uri);

    PublicJwk<?> getJwk();
    JweHeader setJwk(PublicJwk<?> jwk);

    String getKeyId();
    JweHeader setKeyId(String kid);

    URI getX509Url();
    JweHeader setX509Url(URI uri);

    List<X509Certificate> getX509CertificateChain();
    JweHeader setX509CertificateChain(List<X509Certificate> chain);

    byte[] getX509CertificateSha1Thumbprint();
    JweHeader setX509CertificateSha1Thumbprint(byte[] thumbprint);
    JweHeader computeX509CertificateSha1Thumbprint();

    byte[] getX509CertificateSha256Thumbprint();
    JweHeader setX509CertificateSha256Thumbprint(byte[] thumbprint);
    JweHeader computeX509CertificateSha256Thumbprint();

    Set<String> getCritical();
    JweHeader setCritical(Set<String> crit);

    int getPbes2Count();
    JweHeader setPbes2Count(int count);

    byte[] getPbes2Salt();
    JweHeader setPbes2Salt(byte[] salt);

    byte[] getAgreementPartyUInfo();
    String getAgreementPartyUInfoString();
    JweHeader setAgreementPartyUInfo(byte[] info);
    JweHeader setAgreementPartyUInfo(String info);

    byte[] getAgreementPartyVInfo();
    String getAgreementPartyVInfoString();
    JweHeader setAgreementPartyVInfo(byte[] info);
    JweHeader setAgreementPartyVInfo(String info);
}

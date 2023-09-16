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
package io.jsonwebtoken.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Mutation (modifications) of X.509-specific properties of an associated JWT Header or JWK, enabling method chaining.
 *
 * @param <T> the mutator subtype, for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface X509Mutator<T extends X509Mutator<T>> {

    /**
     * Sets the {@code x5u} (X.509 URL) that refers to a resource containing the X.509 public key certificate or
     * certificate chain of the associated JWT or JWK. A {@code null} value will remove the property from the JSON map.
     *
     * <p>The URI <em>MUST</em> refer to a resource for an X.509 public key certificate or certificate chain that
     * conforms to <a href="https://datatracker.ietf.org/doc/html/rfc5280">RFC 5280</a> in PEM-encoded form, with
     * each certificate delimited as specified in
     * <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.
     * The key in the first certificate <em>MUST</em> match the public key represented by other members of the
     * associated JWT or JWK.  The protocol used to acquire the resource <em>MUST</em> provide integrity protection;
     * an HTTP GET request to retrieve the certificate <em>MUST</em> use
     * <a href="https://datatracker.ietf.org/doc/html/rfc2818">HTTP over TLS</a>; the identity of the server
     * <em>MUST</em> be validated, as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc6125#section-6">Section 6 of RFC 6125</a>.</p>
     *
     * <ul>
     *     <li>When set for a {@link JwsHeader}, the certificate or first certificate in the chain contains
     *         the public key complement of the private key used to digitally sign the JWS.</li>
     *     <li>When set for {@link JweHeader}, the certificate or first certificate in the chain contains the
     *         public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When set for an {@link AsymmetricJwk}, the certificate or first certificate in the chain
     *         <em>MUST</em> contain the public key represented by the JWK.</li>
     * </ul>
     *
     * @param uri the {@code x5u} (X.509 URL) that refers to a resource for the X.509 public key certificate or
     *            certificate chain associated with the JWT or JWK.
     * @return the mutator/builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6">JWK <code>x5u</code> (X.509 URL) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5">JWS <code>x5u</code> (X.509 URL) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7">JWE <code>x5u</code> (X.509 URL) Header Parameter</a>
     */
    T x509Url(URI uri);

    /**
     * Sets the {@code x5c} (X.509 Certificate Chain) of the associated JWT or JWK. A {@code null} value will remove the
     * property from the JSON map. The initial certificate <em>MAY</em> be followed by additional certificates, with
     * each subsequent certificate being the one used to certify the previous one.
     *
     * <ul>
     *     <li>When set for a {@link JwsHeader}, the first certificate (at list index 0) <em>MUST</em> contain
     *         the public key complement of the private key used to digitally sign the JWS.</li>
     *     <li>When set for {@link JweHeader}, the first certificate (at list index 0) <em>MUST</em> contain the
     *         public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When set for an {@link AsymmetricJwk}, the first certificate (at list index 0) <em>MUST</em> contain
     *         the public key represented by the JWK.</li>
     * </ul>
     *
     * @param chain the {@code x5c} (X.509 Certificate Chain) of the associated JWT or JWK.
     * @return the header/builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7">JWK <code>x5c</code> (X.509 Certificate Chain) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6">JWS <code>x5c</code> (X.509 Certificate Chain) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8">JWE <code>x5c</code> (X.509 Certificate Chain) Header Parameter</a>
     */
    T x509CertificateChain(List<X509Certificate> chain);

    /**
     * Sets the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT or JWK. A {@code null} value will remove the
     * property from the JSON map.
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * <ul>
     *     <li>When set for a {@link JwsHeader}, it is the SHA-1 thumbprint of the X.509 certificate complement of
     *         the private key used to digitally sign the JWS.</li>
     *     <li>When set for {@link JweHeader}, it is the thumbprint of the X.509 Certificate containing the
     *         public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When set for an {@link AsymmetricJwk}, it is the thumbprint of the X.509 certificate containing the
     *         public key represented by the JWK.</li>
     * </ul>
     *
     * @param thumbprint the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     *                   X.509 Certificate associated with the JWT or JWK
     * @return the header for method chaining
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8">JWK <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7">JWS <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9">JWE <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     */
    T x509CertificateSha1Thumbprint(byte[] thumbprint);

    /**
     * Sets the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * X.509 Certificate associated with the JWT or JWK. A {@code null} value will remove the
     * property from the JSON map.
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * <ul>
     *     <li>When set for a {@link JwsHeader}, it is the SHA-256 thumbprint of the X.509 certificate complement
     *         of the private key used to digitally sign the JWS.</li>
     *     <li>When set for {@link JweHeader}, it is the SHA-256 thumbprint of the X.509 Certificate containing the
     *         public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When set for a {@link AsymmetricJwk}, it is the SHA-256 thumbprint of the X.509 certificate
     *         containing the public key represented by the JWK.</li>
     * </ul>
     *
     * @param thumbprint the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     *                   X.509 Certificate associated with the JWT or JWK
     * @return the header for method chaining
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.9">JWK <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8">JWS <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10">JWE <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     */
    T x509CertificateSha256Thumbprint(byte[] thumbprint);
}

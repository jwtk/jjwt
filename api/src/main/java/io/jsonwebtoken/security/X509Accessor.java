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
 * Accessor methods of X.509-specific properties of a
 * {@link io.jsonwebtoken.ProtectedHeader ProtectedHeader} or {@link AsymmetricJwk}, guaranteeing consistent behavior
 * across similar but distinct JWT concepts with identical parameter names.
 *
 * @see io.jsonwebtoken.ProtectedHeader
 * @see AsymmetricJwk
 * @since JJWT_RELEASE_VERSION
 */
public interface X509Accessor {

    /**
     * Returns the {@code x5u} (X.509 URL) that refers to a resource for the associated X.509 public key certificate
     * or certificate chain, or {@code null} if not present.
     *
     * <p>When present, the URI <em>MUST</em> refer to a resource for an X.509 public key certificate or certificate
     * chain that conforms to <a href="https://datatracker.ietf.org/doc/html/rfc5280">RFC 5280</a> in PEM-encoded form,
     * with each certificate delimited as specified in
     * <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.
     * The key in the first certificate <em>MUST</em> match the public key represented by other members of the
     * associated ProtectedHeader or JWK.  The protocol used to acquire the resource <em>MUST</em> provide integrity
     * protection; an HTTP GET request to retrieve the certificate <em>MUST</em> use
     * <a href="https://datatracker.ietf.org/doc/html/rfc2818">HTTP over TLS</a>; the identity of the server
     * <em>MUST</em> be validated, as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc6125#section-6">Section 6 of RFC 6125</a>.</p>
     *
     * <ul>
     *     <li>When present in a {@link JwsHeader}, the certificate or first certificate in the chain corresponds
     *         the public key complement of the private key used to digitally sign the JWS.</li>
     *     <li>When present in a {@link JweHeader}, the certificate or certificate chain corresponds to the
     *         public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When present in an {@link AsymmetricJwk}, the certificate or first certificate in the chain
     *         <em>MUST</em> contain the public key represented by the JWK.</li>
     * </ul>
     *
     * @return the {@code x5u} (X.509 URL) that refers to a resource for the associated X.509 public key certificate or
     * certificate chain.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6">JWK {@code x5u} (X.509 URL) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5">JWS {@code x5u} (X.509 URL) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7">JWE {@code x5u} (X.509 URL) Header Parameter</a>
     */
    URI getX509Url();

    /**
     * Returns the associated {@code x5c} (X.509 Certificate Chain), or {@code null} if not present. The initial
     * certificate <em>MAY</em> be followed by additional certificates, with each subsequent certificate being the
     * one used to certify the previous one.
     *
     * <ul>
     *     <li>When present in a {@link JwsHeader}, the first certificate (at list index 0) <em>MUST</em> contain
     *         the public key complement of the private key used to digitally sign the JWS.</li>
     *     <li>When present in a {@link JweHeader}, the first certificate (at list index 0) <em>MUST</em> contain
     *         the public key to which the JWE was encrypted, and may be used to determine the private key needed to
     *         decrypt the JWE.</li>
     *     <li>When present in an {@link AsymmetricJwk}, the first certificate (at list index 0)
     *         <em>MUST</em> contain the public key represented by the JWK.</li>
     * </ul>
     *
     * @return the associated {@code x5c} (X.509 Certificate Chain), or {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7">JWK <code>x5c</code> (X.509 Certificate Chain) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6">JWS <code>x5c</code> (X.509 Certificate Chain) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8">JWE <code>x5c</code> (X.509 Certificate Chain) Header Parameter</a>
     */
    List<X509Certificate> getX509CertificateChain();

    /**
     * Returns the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * associated X.509 Certificate, or {@code null} if not present.
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * <ul>
     *     <li>When present in a {@link JwsHeader}, it is the SHA-1 thumbprint of the X.509 certificate complement
     *         of the private key used to digitally sign the JWS.</li>
     *     <li>When present in a {@link JweHeader}, it is the SHA-1 thumbprint of the X.509 Certificate containing
     *         the public key to which the JWE was encrypted, and may be used to determine the private key
     *         needed to decrypt the JWE.</li>
     *     <li>When present in an {@link AsymmetricJwk}, it is the SHA-1 thumbprint of the X.509 certificate
     *         containing the public key represented by the JWK.</li>
     * </ul>
     *
     * @return the {@code x5t} (X.509 Certificate SHA-1 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * associated X.509 Certificate, or {@code null} if not present
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8">JWK <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7">JWS <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9">JWE <code>x5t</code> (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
     */
    byte[] getX509CertificateSha1Thumbprint();

    /**
     * Returns the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * associated X.509 Certificate, or {@code null} if not present.
     *
     * <p>Note that certificate thumbprints are also sometimes known as certificate fingerprints.</p>
     *
     * <ul>
     *     <li>When present in a {@link JwsHeader}, it is the SHA-256 thumbprint of the X.509 certificate complement
     *         of the private key used to digitally sign the JWS.</li>
     *     <li>When present in a {@link JweHeader}, it is the SHA-256 thumbprint of the X.509 Certificate containing
     *         the public key to which the JWE was encrypted, and may be used to determine the private key
     *         needed to decrypt the JWE.</li>
     *     <li>When present in an {@link AsymmetricJwk}, it is the SHA-256 thumbprint of the X.509 certificate
     *         containing the public key represented by the JWK.</li>
     * </ul>
     *
     * @return the {@code x5t#S256} (X.509 Certificate SHA-256 Thumbprint) (a.k.a. digest) of the DER-encoding of the
     * associated X.509 Certificate, or {@code null} if not present
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.9">JWK <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8">JWS <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10">JWE <code>x5t#S256</code> (X.509 Certificate SHA-256 Thumbprint) Header Parameter</a>
     */
    byte[] getX509CertificateSha256Thumbprint();
}

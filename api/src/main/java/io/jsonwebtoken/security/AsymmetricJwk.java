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

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * JWK representation of an asymmetric (public or private) cryptographic key.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricJwk<K extends Key> extends Jwk<K> {

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">{@code use} (Public Key Use)
     * parameter</a> value or {@code null} if not present. {@code use} values are CaSe-SeNsItIvE.
     *
     * <p>The JWK specification <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">defines</a> the
     * following {@code use} values:</p>
     *
     * <table summary="JWK Key Use Values">
     * <caption>JWK Key Use Values</caption>
     * <thead>
     * <tr>
     * <th>Value</th>
     * <th>Key Use</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td><b>{@code sig}</b></td>
     * <td>signature</td>
     * </tr>
     * <tr>
     * <td><b>{@code enc}</b></td>
     * <td>encryption</td>
     * </tr>
     * </tbody>
     * </table>
     *
     * <p>Other values <em>MAY</em> be used.  For best interoperability with other applications however, it is
     * recommended to use only the values above.</p>
     *
     * <p>When a key is used to wrap another key and a public key use designation for the first key is desired, the
     * {@code enc} (encryption) key use value is used, since key wrapping is a kind of encryption.  The
     * {@code enc} value is also to be used for public keys used for key agreement operations.</p>
     *
     * <p><b>Public Key Use vs Key Operations</b></p>
     *
     * <p>Per
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">JWK RFC 7517, Section 4.3, last paragraph</a>,
     * the {@code use} (Public Key Use) and {@link #getOperations() key_ops (Key Operations)} members
     * <em>SHOULD NOT</em> be used together; however, if both are used, the information they convey <em>MUST</em> be
     * consistent.  Applications should specify which of these members they use, if either is to be used by the
     * application.</p>
     *
     * @return the JWK {@code use} value or {@code null} if not present.
     */
    String getPublicKeyUse();

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.6">{@code x5u} (X.509 URL)
     * parameter</a> value as a {@link URI} instance, or {@code null} if not present.
     *
     * <p>If present, the URI <em>MUST</em> refer to a
     * resource for an X.509 public key certificate or certificate chain that conforms to
     * <a href="https://datatracker.ietf.org/doc/html/rfc5280">RFC 5280</a> in PEM-encoded form, with each certificate
     * delimited as specified in
     * <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.
     * The key in the first certificate <em>MUST</em> match the public key represented by other members of
     * the JWK.  The protocol used to acquire the resource <em>MUST</em> provide integrity protection; an HTTP GET
     * request to retrieve the certificate <em>MUST</em> use
     * <a href="https://datatracker.ietf.org/doc/html/rfc2818">HTTP over TLS</a>; the identity of the server
     * <em>MUST</em> be validated, as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc6125#section-6">Section 6 of RFC 6125</a>. Use of this
     * parameter is OPTIONAL.</p>
     *
     * <p>While there is no requirement that optional JWK members providing key usage, algorithm, or other
     * information be present when the {@code x5u} member is used, doing so may improve interoperability for
     * applications that do not handle
     * <a href="https://datatracker.ietf.org/doc/html/rfc5280">PKIX certificates [RFC5280]</a>.  If other members
     * are present, the contents of those members <em>MUST</em> be semantically consistent with the related fields
     * in the first certificate.  For instance, if the {@link #getPublicKeyUse() use (Public Key Use)} member is
     * present, then it <em>MUST</em> correspond to the usage that is specified in the certificate, when it includes
     * this information.  Similarly, if the {@link #getAlgorithm() alg (Algorithm)} member is present, it
     * <em>MUST</em> correspond to the algorithm specified in the certificate.</p>
     *
     * @return the JWK {@code x5u} value as a {@link URI} instance or {@code null} if not present.
     */
    URI getX509Url();

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.7">{@code x5c} (X.509 Certificate Chain)
     * parameter</a> value as a type-safe <code>List&lt;{@link X509Certificate}&gt;</code>, or
     * {@code null} if not present.
     *
     * <p>The certificate chain is a {@code List} of {@link X509Certificate}s.  The certificate containing the
     * key value <em>MUST</em> be the first in the list (at index {@code 0}).  This <em>MAY</em> be
     * followed by additional certificates, with each subsequent certificate being the one used to certify the
     * previous one.  The key in the first certificate <em>MUST</em> match the public key represented by other
     * members of the JWK.</p>
     *
     * @return the JWK {@code x5c} value as a type-safe <code>List&lt;{@link X509Certificate}&gt;</code> or
     * {@code null} if not present.
     */
    List<X509Certificate> getX509CertificateChain();

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.8">{@code x5t} (X.509 Certificate SHA-1
     * Thumbprint) parameter</a> value (aka SHA-1 'fingerprint') as a type-safe {@code byte[]}, or {@code null}
     * if not present.
     *
     * <p>The key in the certificate <em>MUST</em> match the public key represented by other members of the JWK.</p>
     *
     * <p>As with the {@link #getX509Url()} method, optional JWK members providing key usage, algorithm, or other
     * information <em>MAY</em> also be present when the {@code x5t} member is used.  If other members are
     * present, the contents of those members <em>MUST</em> be semantically consistent with the related fields in
     * the referenced certificate.  See the last paragraph of the {@link #getX509Url()} method JavaDoc for
     * additional guidance on this.</p>
     *
     * @return the JWK {@code x5t} value as a type-safe {@code byte[]} or {@code null} if not present.
     */
    byte[] getX509CertificateSha1Thumbprint();

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.9">{@code x5t#256} (X.509 Certificate SHA-256
     * Thumbprint) parameter</a> value (aka SHA-256 'fingerprint') as a type-safe {@code byte[]}, or {@code null}
     * if not present.
     *
     * <p>The key in the certificate <em>MUST</em> match the public key represented by other members of the JWK.</p>
     *
     * <p>As with the {@link #getX509Url()} method, optional JWK members providing key usage, algorithm, or other
     * information <em>MAY</em> also be present when the {@code x5t#256} member is used.  If other members are
     * present, the contents of those members <em>MUST</em> be semantically consistent with the related fields in
     * the referenced certificate.  See the last paragraph of the {@link #getX509Url()} method JavaDoc for
     * additional guidance on this.</p>
     *
     * @return the JWK {@code x5t#256} value as a type-safe {@code byte[]} or {@code null} if not present.
     */
    byte[] getX509CertificateSha256Thumbprint();
}

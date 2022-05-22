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
import java.util.Set;

/**
 * A {@link JwkBuilder} that builds asymmetric (public or private) JWKs.
 *
 * @param <K> the type of Java key provided by the JWK.
 * @param <J> the type of asymmetric JWK created
 * @param <T> the type of the builder, for subtype method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>, T extends AsymmetricJwkBuilder<K, J, T>>
        extends JwkBuilder<K, J, T> {

    /**
     * Sets the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">{@code use} (Public Key Use)
     * parameter</a> value. {@code use} values are CaSe-SeNsItIvE.  A {@code null} value will remove the property
     * from the JWK.
     *
     * <p>The JWK specification <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">defines</a> the
     * following {@code use} values:</p>
     *
     * <table>
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
     * the {@code use} (Public Key Use) and {@link #setOperations(Set) key_ops (Key Operations)} members
     * <em>SHOULD NOT</em> be used together; however, if both are used, the information they convey <em>MUST</em> be
     * consistent. Applications should specify which of these members they use, if either is to be used by the
     * application.</p>
     *
     * @param use the JWK {@code use} value.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if the {@code use} value is {@code null} or empty.
     */
    T setPublicKeyUse(String use) throws IllegalArgumentException;

    /**
     * Sets the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.7">{@code x5c} (X.509 Certificate Chain)
     * parameter</a> value as a type-safe <code>List&lt;{@link X509Certificate}&gt;</code>.
     *
     * <p>The certificate chain is a {@code List} of {@link X509Certificate}s.  The certificate containing the
     * key value <em>MUST</em> be the first in the list (at list index {@code 0}).  This <em>MAY</em> be
     * followed by additional certificates, with each subsequent certificate being the one used to certify the
     * previous one.  The key in the first certificate <em>MUST</em> match the public key represented by other
     * members of the JWK.</p>
     *
     * @param chain the JWK {@code x5c} value as a type-safe <code>List&lt;{@link X509Certificate}&gt;</code>.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if the {@code chain} is null or empty.
     */
    T setX509CertificateChain(List<X509Certificate> chain) throws IllegalArgumentException;

    /**
     * Sets the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.6">{@code x5u} (X.509 URL)
     * parameter</a> value as a {@link URI} instance. A {@code null} value will remove the property from the JWK.
     *
     * <p>The URI <em>MUST</em> refer to a resource for an X.509 public key certificate or certificate chain that
     * conforms to <a href="https://datatracker.ietf.org/doc/html/rfc5280">RFC 5280</a> in PEM-encoded form, with
     * each certificate delimited as specified in
     * <a href="https://datatracker.ietf.org/doc/html/rfc4945#section-6.1">Section 6.1 of RFC 4945</a>.
     * The key in the first certificate <em>MUST</em> match the public key represented by other members of
     * the JWK.  The protocol used to acquire the resource <em>MUST</em> provide integrity protection; an HTTP GET
     * request to retrieve the certificate <em>MUST</em> use
     * <a href="https://datatracker.ietf.org/doc/html/rfc2818">HTTP over TLS</a>; the identity of the server
     * <em>MUST</em> be validated, as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc6125#section-6">Section 6 of RFC 6125</a>.
     *
     * <p>While there is no requirement that optional JWK members providing key usage, algorithm, or other
     * information be present when the {@code x5u} member is used, doing so may improve interoperability for
     * applications that do not handle
     * <a href="https://datatracker.ietf.org/doc/html/rfc5280">PKIX certificates [RFC5280]</a>.  If other members
     * are present, the contents of those members <em>MUST</em> be semantically consistent with the related fields
     * in the first certificate.  For instance, if the {@link #setPublicKeyUse(String) use (Public Key Use)} value is
     * set, then it <em>MUST</em> correspond to the usage that is specified in the certificate, when it includes
     * this information.  Similarly, if the {@link #setAlgorithm(String) alg (Algorithm)} value is present, it
     * <em>MUST</em> correspond to the algorithm specified in the certificate.</p>
     *
     * @param uri the JWK {@code x5u} X.509 URL value as a {@link URI}.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code uri} is {@code null}.
     */
    T setX509Url(URI uri) throws IllegalArgumentException;

    //T withX509KeyUse(boolean enable);

    T withX509Sha1Thumbprint(boolean enable);

    T withX509Sha256Thumbprint(boolean enable);
}

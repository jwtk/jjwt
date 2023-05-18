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

import java.security.Key;

/**
 * JWK representation of an asymmetric (public or private) cryptographic key.
 *
 * @param <K> the type of {@link java.security.PublicKey} or {@link java.security.PrivateKey} represented by this JWK.
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricJwk<K extends Key> extends Jwk<K>, X509Accessor {

    /**
     * Returns the JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2">{@code use} (Public Key Use)
     * parameter</a> value or {@code null} if not present. {@code use} values are CaSe-SeNsItIvE.
     *
     * <p>The JWK specification <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2">defines</a> the
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
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">JWK RFC 7517, Section 4.3, last paragraph</a>,
     * the {@code use} (Public Key Use) and {@link #getOperations() key_ops (Key Operations)} members
     * <em>SHOULD NOT</em> be used together; however, if both are used, the information they convey <em>MUST</em> be
     * consistent.  Applications should specify which of these members they use, if either is to be used by the
     * application.</p>
     *
     * @return the JWK {@code use} value or {@code null} if not present.
     */
    String getPublicKeyUse();
}

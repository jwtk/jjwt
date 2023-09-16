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
import java.util.Collection;

/**
 * A {@link JwkBuilder} that builds asymmetric (public or private) JWKs.
 *
 * @param <K> the type of Java key provided by the JWK.
 * @param <J> the type of asymmetric JWK created
 * @param <T> the type of the builder, for subtype method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>, T extends AsymmetricJwkBuilder<K, J, T>>
        extends JwkBuilder<K, J, T>, X509Builder<T> {

    /**
     * Sets the JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2">{@code use} (Public Key Use)
     * parameter</a> value. {@code use} values are CaSe-SeNsItIvE.  A {@code null} value will remove the property
     * from the JWK.
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
     * the <code>use (Public Key Use)</code> and {@link #operations(Collection) key_ops (Key Operations)} members
     * <em>SHOULD NOT</em> be used together; however, if both are used, the information they convey <em>MUST</em> be
     * consistent. Applications should specify which of these members they use, if either is to be used by the
     * application.</p>
     *
     * @param use the JWK {@code use} value.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if the {@code use} value is {@code null} or empty.
     */
    T publicKeyUse(String use) throws IllegalArgumentException;
}

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
import java.util.Map;
import java.util.Set;

/**
 * A {@link SecurityBuilder} that produces a JWK.  A JWK is an immutable set of name/value pairs that represent a
 * cryptographic key as defined by
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517: JSON Web Key (JWK)</a>.  The {@code Jwk}.
 * The {@code JwkBuilder} interface represents common JWK properties that may be specified for any type of JWK.
 * Builder subtypes support additional JWK properties specific to different types of cryptographic keys
 * (e.g. Secret, Asymmetric, RSA, Elliptic Curve, etc).</p>
 *
 * @see SecretJwkBuilder
 * @see RsaPublicJwkBuilder
 * @see RsaPrivateJwkBuilder
 * @see EcPublicJwkBuilder
 * @see EcPrivateJwkBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> extends SecurityBuilder<J, T> {

    /**
     * Set a single JWK property by name. If the {@code value} is {@code null}, an  empty
     * {@link java.util.Collection}, or an empty {@link Map}, the property will be removed from the JWK.
     *
     * @param name  the name of the JWK property
     * @param value the value to set for the property name
     * @return the builder for method chaining.
     */
    T put(String name, Object value);

    /**
     * Sets one or more JWK properties by name.  If any {@code name} has a {@code value} that is {@code null},
     * an empty {@link java.util.Collection}, or an empty {@link Map}, the property will be removed from the JWK.
     *
     * @param values one or more name/value pairs to set on the JWK.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code values} is {@code null} or empty.
     */
    T putAll(Map<String, ?> values) throws IllegalArgumentException;

    /**
     * Sets the JWK <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.4">{@code alg} (Algorithm)
     * Parameter</a>.
     *
     * <p>The {@code alg} (algorithm) parameter identifies the algorithm intended for use with the key.  The
     * value specified should either be one of the values in the IANA
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-7.1">JSON Web Signature and Encryption
     * Algorithms</a> registry or be a value that contains a {@code Collision-Resistant Name}.  The {@code alg}
     * must be a CaSe-SeNsItIvE ASCII string.</p>
     *
     * @param alg the JWK {@code alg} value.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code alg} is {@code null} or empty.
     */
    T setAlgorithm(String alg) throws IllegalArgumentException;

    /**
     * Sets the JWK <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">{@code kid} (Key ID)
     * Parameter</a>.
     *
     * <p>The {@code kid} (key ID) parameter is used to match a specific key.  This is used, for instance,
     * to choose among a set of keys within a {@code JWK Set} during key rollover.  The structure of the
     * {@code kid} value is unspecified.  When {@code kid} values are used within a JWK Set, different keys
     * within the {@code JWK Set} <em>SHOULD</em> use distinct {@code kid} values. (One example in which
     * different keys might use the same {@code kid} value is if they have different {@code kty} (key type)
     * values but are considered to be equivalent alternatives by the application using them.)</p>
     *
     * <p>The {@code kid} value is a CaSe-SeNsItIvE string, and it is optional. When used with JWS or JWE,
     * the {@code kid} value is used to match a JWS or JWE {@code kid} Header Parameter value.</p>
     *
     * @param kid the JWK {@code kid} value.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if the argument is {@code null} or empty.
     */
    T setId(String kid) throws IllegalArgumentException;

    /**
     * Sets the JWK <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">{@code key_ops}
     * (Key Operations) Parameter</a> values.
     *
     * <p>The {@code key_ops} (key operations) parameter identifies the operation(s) for which the key is
     * intended to be used.  The {@code key_ops} parameter is intended for use cases in which public,
     * private, or symmetric keys may be present.</p>
     *
     * <p>The JWK specification <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">defines</a> the
     * following values:</p>
     *
     * <table summary="JWK Key Operations">
     * <caption>JWK Key Operations</caption>
     * <thead>
     * <tr>
     * <th>Value</th>
     * <th>Operation</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td><b>{@code sign}</b></td>
     * <td>compute digital signatures or MAC</td>
     * </tr>
     * <tr>
     * <td><b>{@code verify}</b></td>
     * <td>verify digital signatures or MAC</td>
     * </tr>
     * <tr>
     * <td><b>{@code encrypt}</b></td>
     * <td>encrypt content</td>
     * </tr>
     * <tr>
     * <td><b>{@code decrypt}</b></td>
     * <td>decrypt content and validate decryption, if applicable</td>
     * </tr>
     * <tr>
     * <td><b>{@code wrapKey}</b></td>
     * <td>encrypt key</td>
     * </tr>
     * <tr>
     * <td><b>{@code unwrapKey}</b></td>
     * <td>decrypt key and validate decryption, if applicable</td>
     * </tr>
     * <tr>
     * <td><b>{@code deriveKey}</b></td>
     * <td>derive key</td>
     * </tr>
     * <tr>
     * <td><b>{@code deriveBits}</b></td>
     * <td>derive bits not to be used as a key</td>
     * </tr>
     * </tbody>
     * </table>
     *
     * <p>(Note that {@code key_ops} values intentionally match the {@code KeyUsage} values defined in the
     * <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a> specification.)</p>
     *
     * <p>Other values <em>MAY</em> be used.  For best interoperability with other applications however, it is
     * recommended to use only the values above. Each value is a CaSe-SeNsItIvE string.  Use of the
     * {@code key_ops} member is <em>OPTIONAL</em>, unless the application requires its presence.</p>
     *
     * <p>Multiple unrelated key operations <em>SHOULD NOT</em> be specified for a key because of the potential
     * vulnerabilities associated with using the same key with multiple algorithms.  Thus, the combinations
     * {@code sign} with {@code verify}, {@code encrypt} with {@code decrypt}, and {@code wrapKey} with
     * {@code unwrapKey} are permitted, but other combinations <em>SHOULD NOT</em> be used.</p>
     *
     * @param ops the JWK {@code key_ops} value set.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code ops} is {@code null} or empty.
     */
    T setOperations(Set<String> ops) throws IllegalArgumentException;
}

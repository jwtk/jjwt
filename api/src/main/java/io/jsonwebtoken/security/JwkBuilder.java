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

import io.jsonwebtoken.lang.MapMutator;

import java.security.Key;
import java.util.Collection;

/**
 * A {@link SecurityBuilder} that produces a JWK.  A JWK is an immutable set of name/value pairs that represent a
 * cryptographic key as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517: JSON Web Key (JWK)</a>.
 * The {@code JwkBuilder} interface represents common JWK properties that may be specified for any type of JWK.
 * Builder subtypes support additional JWK properties specific to different types of cryptographic keys
 * (e.g. Secret, Asymmetric, RSA, Elliptic Curve, etc).
 *
 * @param <K> the type of Java {@link Key} represented by the constructed JWK.
 * @param <J> the type of {@link Jwk} created by the builder
 * @param <T> the type of the builder, for subtype method chaining
 * @see SecretJwkBuilder
 * @see RsaPublicJwkBuilder
 * @see RsaPrivateJwkBuilder
 * @see EcPublicJwkBuilder
 * @see EcPrivateJwkBuilder
 * @see OctetPublicJwkBuilder
 * @see OctetPrivateJwkBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>>
        extends MapMutator<String, Object, T>, SecurityBuilder<J, T>, KeyOperationPolicied<T> {

    /**
     * Sets the JWK <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4">{@code alg} (Algorithm)
     * Parameter</a>.
     *
     * <p>The {@code alg} (algorithm) parameter identifies the algorithm intended for use with the key.  The
     * value specified should either be one of the values in the IANA
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
     * Algorithms</a> registry or be a value that contains a {@code Collision-Resistant Name}.  The {@code alg}
     * must be a CaSe-SeNsItIvE ASCII string.</p>
     *
     * @param alg the JWK {@code alg} value.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code alg} is {@code null} or empty.
     */
    T algorithm(String alg) throws IllegalArgumentException;

    /**
     * Sets the JWK <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5">{@code kid} (Key ID)
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
    T id(String kid) throws IllegalArgumentException;

    /**
     * Sets the JWK's {@link #id(String) kid} value to be the Base64URL-encoding of its {@code SHA-256}
     * {@link Jwk#thumbprint(HashAlgorithm) thumbprint}.  That is, the constructed JWK's {@code kid} value will equal
     * <code>jwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}({@link Jwks.HASH}.{@link Jwks.HASH#SHA256 SHA256}).{@link JwkThumbprint#toString() toString()}</code>.
     *
     * <p>This is a convenience method that delegates to {@link #idFromThumbprint(HashAlgorithm)} using
     * {@link Jwks.HASH}{@code .}{@link Jwks.HASH#SHA256 SHA256}.</p>
     *
     * @return the builder for method chaining.
     */
    T idFromThumbprint();

    /**
     * Sets the JWK's {@link #id(String) kid} value to be the Base64URL-encoding of its
     * {@link Jwk#thumbprint(HashAlgorithm) thumbprint} using the specified {@link HashAlgorithm}.  That is, the
     * constructed JWK's {@code kid} value will equal
     * <code>{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(alg).{@link JwkThumbprint#toString() toString()}.</code>
     *
     * @param alg the hash algorithm to use to compute the thumbprint.
     * @return the builder for method chaining.
     * @see Jwks.HASH
     */
    T idFromThumbprint(HashAlgorithm alg);

    /**
     * Specifies an operation for which the key may be used by adding it to the
     * JWK <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">{@code key_ops} (Key Operations)
     * Parameter</a> values. This method may be called multiple times.
     *
     * <p>The {@code key_ops} (key operations) parameter identifies the operation(s) for which the key is
     * intended to be used.  The {@code key_ops} parameter is intended for use cases in which public,
     * private, or symmetric keys may be present.</p>
     *
     * <p><b>Security Vulnerability Notice</b></p>
     *
     * <p>Multiple unrelated key operations <em>SHOULD NOT</em> be specified for a key because of the potential
     * vulnerabilities associated with using the same key with multiple algorithms.  Thus, the combinations
     * {@link Jwks.OP#SIGN sign} with {@link Jwks.OP#VERIFY verify},
     * {@link Jwks.OP#ENCRYPT encrypt} with {@link Jwks.OP#DECRYPT decrypt}, and
     * {@link Jwks.OP#WRAP_KEY wrapKey} with {@link Jwks.OP#UNWRAP_KEY unwrapKey} are permitted, but other combinations
     * <em>SHOULD NOT</em> be used.  This is enforced by the builder's key operation
     * {@link #operationPolicy(KeyOperationPolicy) policy}.</p>
     *
     * <p><b>Standard {@code KeyOperation}s and Overrides</b></p>
     *
     * <p>All RFC-standard JWK Key Operations in the {@link Jwks.OP} registry are supported via the builder's default
     * operations {@link #operationPolicy(KeyOperationPolicy) policy}, but other (custom) values
     * <em>MAY</em> be specified (for example, using a {@link Jwks.OP#builder()}).</p>
     *
     * <p>If the {@code JwkBuilder} is being used to rebuild or parse an existing JWK however, any custom operations
     * should be enabled for the {@code JwkBuilder} by {@link #operationPolicy(KeyOperationPolicy) specifying}
     * an operations policy that includes the custom values (e.g. via
     * {@link Jwks.OP#policy()}.{@link KeyOperationPolicyBuilder#add(KeyOperation) add(customKeyOperation)}).</p>
     *
     * <p>For best interoperability with other applications however, it is recommended to use only the {@link Jwks.OP}
     * constants.</p>
     *
     * @param operation the value to add to the JWK {@code key_ops} value set
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code op} is {@code null} or if the operation is not permitted
     *                                  by the operations {@link #operationPolicy(KeyOperationPolicy) policy}.
     * @see Jwks.OP
     */
    T operation(KeyOperation operation) throws IllegalArgumentException;

    /**
     * Sets the JWK <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">{@code key_ops}
     * (Key Operations) Parameter</a> values.
     *
     * <p>The {@code key_ops} (key operations) parameter identifies the operation(s) for which the key is
     * intended to be used.  The {@code key_ops} parameter is intended for use cases in which public,
     * private, or symmetric keys may be present.</p>
     *
     * <p><b>Security Vulnerability Notice</b></p>
     *
     * <p>Multiple unrelated key operations <em>SHOULD NOT</em> be specified for a key because of the potential
     * vulnerabilities associated with using the same key with multiple algorithms.  Thus, the combinations
     * {@link Jwks.OP#SIGN sign} with {@link Jwks.OP#VERIFY verify},
     * {@link Jwks.OP#ENCRYPT encrypt} with {@link Jwks.OP#DECRYPT decrypt}, and
     * {@link Jwks.OP#WRAP_KEY wrapKey} with {@link Jwks.OP#UNWRAP_KEY unwrapKey} are permitted, but other combinations
     * <em>SHOULD NOT</em> be used.  This is enforced by the builder's default
     * operation {@link #operationPolicy(KeyOperationPolicy) policy}.</p>
     *
     * <p><b>Standard {@code KeyOperation}s and Overrides</b></p>
     *
     * <p>All RFC-standard JWK Key Operations in the {@link Jwks.OP} registry are supported via the builder's default
     * operations {@link #operationPolicy(KeyOperationPolicy) policy}, but other (custom) values
     * <em>MAY</em> be specified (for example, using a {@link Jwks.OP#builder()}).</p>
     *
     * <p>If the {@code JwkBuilder} is being used to rebuild or parse an existing JWK however, any custom operations
     * should be enabled for the {@code JwkBuilder} by {@link #operationPolicy(KeyOperationPolicy) specifying}
     * an operations policy that includes the custom values (e.g. via
     * {@link Jwks.OP#policy()}.{@link KeyOperationPolicyBuilder#add(KeyOperation) add(customKeyOperation)}).</p>
     *
     * <p>For best interoperability with other applications however, it is recommended to use only the {@link Jwks.OP}
     * constants.</p>
     *
     * @param ops the JWK {@code key_ops} value set, or {@code null} if not present.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException {@code ops} is {@code null} or empty, or if any of the operations are not
     *                                  permitted by the operations {@link #operationPolicy(KeyOperationPolicy) policy}.
     * @see Jwks.OP
     */
    T operations(Collection<KeyOperation> ops) throws IllegalArgumentException;
}

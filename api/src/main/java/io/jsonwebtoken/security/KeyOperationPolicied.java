/*
 * Copyright © 2023 jsonwebtoken.io
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

import java.util.function.Consumer;

/**
 * A marker interface that indicates the implementing instance supports the ability to configure a
 * {@link KeyOperationPolicy} used to validate JWK instances.
 *
 * @param <T> the implementing instance for method chaining
 */
@SuppressWarnings("SpellCheckingInspection")
@FunctionalInterface
public interface KeyOperationPolicied<T extends KeyOperationPolicied<T>> {

    /**
     * Sets the key operation policy that determines which {@link KeyOperation}s may be assigned to a JWK.
     *
     * <p>Unless overridden by this method, the default RFC-recommended policy is used where:</p>
     * <ul>
     *     <li>All {@link Jwk.op RFC-standard key operations} are supported.</li>
     *     <li>Multiple unrelated operations may <b>not</b> be assigned to the JWK per the
     *     <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">RFC 7517, Section 4.3</a> recommendation:
     * <blockquote><pre>
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.  Thus, the combinations "{@link Jwk.op#SIGN sign}"
     * with "{@link Jwk.op#VERIFY verify}", "{@link Jwk.op#ENCRYPT encrypt}" with "{@link Jwk.op#DECRYPT decrypt}", and "{@link Jwk.op#WRAP_KEY wrapKey}" with
     * "{@link Jwk.op#UNWRAP_KEY unwrapKey}" are permitted, but other combinations SHOULD NOT be used.</pre></blockquote>
     * </li>
     * </ul>
     *
     * <p>If you wish to enable a different policy, perhaps to support additional custom {@code KeyOperation} values,
     * one may be created and configured using the {@link #operationPolicy(Consumer)} method, or by using a
     * {@link Jwk.op#policy()} builder, or by implementing the {@link KeyOperationPolicy} interface directly.</p>
     *
     * @param policy the policy that determines which {@link KeyOperation}s may be assigned to a JWK.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code policy} is null
     * @see #operationPolicy(Consumer)
     */
    T operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException;

    /**
     * Configures a new {@link KeyOperationPolicy} that determines which {@link KeyOperation}s may be assigned to a
     * JWK. Unless overridden by this or the {@link #operationPolicy(KeyOperationPolicy)} methods, the default
     * RFC-recommended policy is used where:
     * <ul>
     *     <li>All {@link Jwk.op RFC-standard key operations} are supported.</li>
     *     <li>Multiple unrelated operations may <b>not</b> be assigned to the JWK per the
     *     <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">RFC 7517, Section 4.3</a> recommendation:
     * <blockquote><pre>
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.  Thus, the combinations "{@link Jwk.op#SIGN sign}"
     * with "{@link Jwk.op#VERIFY verify}", "{@link Jwk.op#ENCRYPT encrypt}" with "{@link Jwk.op#DECRYPT decrypt}", and "{@link Jwk.op#WRAP_KEY wrapKey}" with
     * "{@link Jwk.op#UNWRAP_KEY unwrapKey}" are permitted, but other combinations SHOULD NOT be used.</pre></blockquote>
     * </li>
     * </ul>
     *
     * @param p the consumer that may configure the policy that determines which {@link KeyOperation}s may be assigned
     *          to a JWK.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code policy} is null
     * @see #operationPolicy(KeyOperationPolicy)
     * @since JJWT_RELEASE_VERSION
     */
    default T operationPolicy(Consumer<KeyOperationPolicyBuilder> p) throws IllegalArgumentException {
        KeyOperationPolicyBuilder b = Jwk.op.policy();
        p.accept(b);
        KeyOperationPolicy policy = b.build();
        return operationPolicy(policy);
    }

}

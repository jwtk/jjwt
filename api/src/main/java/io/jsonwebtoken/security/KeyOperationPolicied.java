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

/**
 * A marker interface that indicates the implementing instance supports the ability to configure a
 * {@link KeyOperationPolicy} used to validate JWK instances.
 *
 * @param <T> the implementing instance for method chaining
 */
public interface KeyOperationPolicied<T extends KeyOperationPolicied<T>> {

    /**
     * Sets the key operation policy that determines which {@link KeyOperation}s may be assigned to a
     * JWK. Unless overridden by this method, the default RFC-recommended policy is used where:
     * <ul>
     *     <li>All {@link Jwks.OP RFC-standard key operations} are supported.</li>
     *     <li>Multiple unrelated operations may <b>not</b> be assigned to the JWK per the
     *     <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">RFC 7517, Section 4.3</a> recommendation:
     * <blockquote><pre>
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.
     * </pre></blockquote></li>
     * </ul>
     *
     * <p>If you wish to enable a different policy, perhaps to support additional custom {@code KeyOperation} values,
     * one can be created by using the {@link Jwks.OP#policy()} builder, or by implementing the
     * {@link KeyOperationPolicy} interface directly.</p>
     *
     * @param policy the policy that determines which {@link KeyOperation}s may be assigned to a JWK.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code policy} is null
     */
    T operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException;
}

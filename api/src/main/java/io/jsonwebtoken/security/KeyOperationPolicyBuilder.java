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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Builder;

import java.util.Collection;


/**
 * A {@code KeyOperationPolicyBuilder} produces a {@link KeyOperationPolicy} that determines
 * which {@link KeyOperation}s may be assigned to a JWK. Custom {@code KeyOperation}s (such as those created by a
 * {@link Jwks.OP#builder()}) may be added to a policy via the {@link #add(KeyOperation)} or {@link #add(Collection)}
 * methods.
 *
 * @see Jwks.OP#policy()
 * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
 * @see Jwks.OP#builder()
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyOperationPolicyBuilder extends Builder<KeyOperationPolicy> {

    /**
     * Sets if a JWK is allowed to have unrelated {@link KeyOperation}s in its {@code key_ops} parameter values.
     * The default value is {@code false} per the JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">RFC 7517, Section 4.3</a> recommendation:
     *
     * <blockquote><pre>
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.
     * </pre></blockquote>
     *
     * <p>Only set this value to {@code true} if you fully understand the security implications of using the same key
     * with multiple algorithms in your application. Otherwise it is best not to use this builder method, or
     * explicitly set it to {@code false}.</p>
     *
     * @param allow if a JWK is allowed to have unrelated key {@link KeyOperation}s in its {@code key_ops}
     *              parameter values.
     * @return the builder for method chaining
     */
    KeyOperationPolicyBuilder allowUnrelated(boolean allow);

    /**
     * Adds the specified key operation to the policy's total set of supported key operations
     * used to validate a key's intended usage, replacing any existing one with an identical (CaSe-SeNsItIvE)
     * {@link Identifiable#getId() id}.
     *
     * <p><b>Standard {@code KeyOperation}s and Overrides</b></p>
     *
     * <p>The RFC standard {@link Jwks.OP} key operations are supported by default and do not need
     * to be added via this method, but beware: <b>If the {@code op} argument has a JWK standard
     * {@link Identifiable#getId() id}, it will replace the JJWT standard operation implementation</b>.
     * This is to allow application developers to favor their own implementations over JJWT's default implementations
     * if necessary (for example, to support legacy or custom behavior).</p>
     *
     * <p>If a custom {@code KeyOperation} is desired, one may be easily created with a {@link Jwks.OP#builder()}.</p>
     *
     * @param op a key operation to add to the policy's total set of supported operations, replacing any
     *           existing one with the same exact (CaSe-SeNsItIvE) {@link KeyOperation#getId() id}.
     * @return the builder for method chaining.
     * @see Jwks.OP
     * @see Jwks.OP#builder()
     * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
     * @see JwkBuilder#operations(Collection)
     */
    KeyOperationPolicyBuilder add(KeyOperation op);

    /**
     * Adds the specified key operations to the policy's total set of supported key operations
     * used to validate a key's intended usage, replacing any existing ones with identical
     * {@link Identifiable#getId() id}s.
     *
     * <p>There may be only one registered {@code KeyOperation} per CaSe-SeNsItIvE {@code id}, and the
     * {@code ops} collection is added in iteration order; if a duplicate id is found when iterating the {@code ops}
     * collection, the later operation will evict any existing operation with the same {@code id}.</p>
     *
     * <p><b>Standard {@code KeyOperation}s and Overrides</b></p>
     *
     * <p>The RFC standard {@link Jwks.OP} key operations are supported by default and do not need
     * to be added via this method, but beware: <b>any operation in the {@code ops} argument with a
     * JWK standard {@link Identifiable#getId() id} will replace the JJWT standard operation implementation</b>.
     * This is to allow application developers to favor their own implementations over JJWT's default implementations
     * if necessary (for example, to support legacy or custom behavior).</p>
     *
     * <p>If custom {@code KeyOperation}s are desired, they may be easily created with a {@link Jwks.OP#builder()}.</p>
     *
     * @param ops collection of key operations to add to the policy's total set of supported operations, replacing any
     *            existing ones with the same exact (CaSe-SeNsItIvE) {@link KeyOperation#getId() id}s.
     * @return the builder for method chaining.
     * @see Jwks.OP
     * @see Jwks.OP#builder()
     * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
     * @see JwkBuilder#operations(Collection)
     */
    KeyOperationPolicyBuilder add(Collection<KeyOperation> ops);

}

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

import io.jsonwebtoken.lang.Builder;

import java.util.Collection;

/**
 * A {@code KeyOperationBuilder} produces {@link KeyOperation} instances that may be added to a JWK's
 * {@link JwkBuilder#operations(Collection) key operations} parameter. This is primarily only useful for creating
 * custom (non-standard) {@code KeyOperation}s for use with a custom {@link KeyOperationPolicy}, as all standard ones
 * are available already via the {@link Jwks.OP} registry singleton.
 *
 * @see Jwks.OP#builder()
 * @see Jwks.OP#policy()
 * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyOperationBuilder extends Builder<KeyOperation> {

    /**
     * Sets the CaSe-SeNsItIvE {@link KeyOperation#getId() id} expected to be unique compared to all other
     * {@code KeyOperation}s.
     *
     * @param id the key operation id
     * @return the builder for method chaining
     */
    KeyOperationBuilder id(String id);

    /**
     * Sets the key operation {@link KeyOperation#getDescription() description}.
     *
     * @param description the key operation description
     * @return the builder for method chaining
     */
    KeyOperationBuilder description(String description);

    /**
     * Indicates that the {@code KeyOperation} with the given {@link KeyOperation#getId() id} is cryptographically
     * related (and complementary) to this one, and may be specified together in a JWK's
     * {@link Jwk#getOperations() operations} set.
     *
     * <p>More concretely, calling this method will ensure the following:</p>
     * <blockquote><pre>
     *     KeyOperation built = Jwks.operation()&#47;*...*&#47;.related(otherId).build();
     *     KeyOperation other = getKeyOperation(otherId);
     *     assert built.isRelated(other);</pre></blockquote>
     *
     * <p>A {@link JwkBuilder}'s key operation {@link JwkBuilder#operationPolicy(KeyOperationPolicy) policy} is likely
     * to {@link KeyOperationPolicyBuilder#allowUnrelated(boolean) reject} any <em>un</em>related operations specified
     * together due to the potential security vulnerabilities that could occur.</p>
     *
     * <p>This method may be called multiple times to add/append a related {@code id} to the constructed
     * {@code KeyOperation}'s total set of related ids.</p>
     *
     * @param id the id of a KeyOperation that will be considered cryptographically related to this one.
     * @return the builder for method chaining.
     * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
     */
    KeyOperationBuilder related(String id);
}

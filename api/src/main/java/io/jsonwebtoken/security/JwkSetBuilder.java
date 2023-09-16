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

import io.jsonwebtoken.lang.MapMutator;

import java.security.Provider;
import java.util.Collection;

/**
 * A builder that produces {@link JwkSet}s containing {@link Jwk}s. {@code Jwk}s with any key
 * {@link Jwk#getOperations() operations} will be validated by
 * the {@link #operationPolicy(KeyOperationPolicy) operationPolicy} first before being added.
 *
 * @see #operationPolicy(KeyOperationPolicy)
 * @see #provider(Provider)
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkSetBuilder extends MapMutator<String, Object, JwkSetBuilder>,
        SecurityBuilder<JwkSet, JwkSetBuilder>, KeyOperationPolicied<JwkSetBuilder> {

    /**
     * Appends the specified {@code jwk} to the set. If the {@code jwk} has any key
     * {@link Jwk#getOperations() operations}, it will be validated with the
     * {@link #operationPolicy(KeyOperationPolicy) operationPolicy} first before being added.
     *
     * @param jwk the jwk to add to the JWK Set. A {@code null} {@code jwk} is ignored.
     * @return the builder for method chaining
     */
    JwkSetBuilder add(Jwk<?> jwk);

    /**
     * Appends the specified {@code Jwk} collection to the JWK Set. If any {@code Jwk} in the collection has
     * any key {@link Jwk#getOperations() operations}, it will be validated with the
     * {@link #operationPolicy(KeyOperationPolicy) operationPolicy} first before being added.
     *
     * @param c the collection of {@code Jwk}s to add to the JWK Set. A {@code null} or empty collection is ignored.
     * @return the builder for method chaining
     */
    JwkSetBuilder add(Collection<Jwk<?>> c);

    /**
     * Sets the {@code JwkSet} {@code keys} parameter value; per standard Java setter idioms, this is a
     * <em>full replacement</em> operation, removing any previous keys from the set.  A {@code null} or empty
     * collection removes all keys from the set.
     *
     * @param c the (possibly null or empty) collection of {@code Jwk}s to set as the JWK set {@code keys} parameter
     *          value.
     * @return the builder for method chaining
     */
    JwkSetBuilder keys(Collection<Jwk<?>> c);

}

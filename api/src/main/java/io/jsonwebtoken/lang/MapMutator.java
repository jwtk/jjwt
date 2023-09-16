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
package io.jsonwebtoken.lang;

import java.util.Map;

/**
 * Mutation (modifications) to a {@link Map} instance while also supporting method chaining. The Map interface's
 * {@link Map#put(Object, Object)}, {@link Map#remove(Object)}, {@link Map#putAll(Map)}, and {@link Map#clear()}
 * mutation methods do not support method chaining, so this interface enables that behavior.
 *
 * @param <K> map key type
 * @param <V> map value type
 * @param <T> the mutator subtype, for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface MapMutator<K, V, T extends MapMutator<K, V, T>> {

    /**
     * Removes the map entry with the specified key.
     * <p>This method is the same as {@link Map#remove Map.remove}, but instead returns the mutator instance for
     * method chaining.</p>
     *
     * @param key the key for the map entry to remove.
     * @return the mutator/builder for method chaining.
     */
    T delete(K key);

    /**
     * Removes all entries from the map. The map will be empty after this call returns.
     * <p>This method is the same as {@link Map#clear Map.clear}, but instead returns the mutator instance for
     * method chaining.</p>
     *
     * @return the mutator/builder for method chaining.
     */
    T empty();

    /**
     * Sets the specified key/value pair in the map, overwriting any existing entry with the same key.
     * A {@code null} or empty value will remove the entry from the map entirely.
     *
     * <p>This method is the same as {@link Map#put Map.put}, but instead returns the mutator instance for
     * method chaining.</p>
     *
     * @param key   the map key
     * @param value the value to set for the specified header parameter name
     * @return the mutator/builder for method chaining.
     */
    T add(K key, V value);

    /**
     * Sets the specified key/value pairs in the map, overwriting any existing entries with the same keys.
     * If any pair has a {@code null} or empty value, that pair will be removed from the map entirely.
     *
     * <p>This method is the same as {@link Map#putAll Map.putAll}, but instead returns the mutator instance for
     * method chaining.</p>
     *
     * @param m the map to add
     * @return the mutator/builder for method chaining.
     */
    T add(Map<? extends K, ? extends V> m);
}

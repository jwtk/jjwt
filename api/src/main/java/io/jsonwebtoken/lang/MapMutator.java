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
     * Sets the specified name/value pair in the map.  A {@code null} or empty value will remove the property
     * from the map entirely.
     *
     * @param key   the map key
     * @param value the value to set for the specified header parameter name
     * @return the mutator/builder for method chaining.
     */
    T put(K key, V value);

    /**
     * Removes the map entry with the specified key
     *
     * @param key the key for the map entry to remove.
     * @return the mutator/builder for method chaining.
     */
    T remove(K key);

    /**
     * Sets the specified name/value pairs in the map.  If any name has a {@code null} or empty value, that
     * map entry will be removed from the map entirely.
     *
     * @param m the map to add
     * @return the mutator/builder for method chaining.
     */
    T putAll(Map<? extends K, ? extends V> m);

    /**
     * Removes all entries from the map. The map will be empty after this call returns.
     *
     * @return the mutator/builder for method chaining.
     */
    T clear();
}

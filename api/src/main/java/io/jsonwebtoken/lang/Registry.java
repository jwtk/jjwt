/*
 * Copyright © 2020 jsonwebtoken.io
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

import java.util.Collection;

/**
 * An immutable read-only repository of key-value pairs.
 *
 * @param <K> key type
 * @param <V> value type
 * @since JJWT_RELEASE_VERSION
 */
public interface Registry<K, V> {

    /**
     * Returns all registry values as a read-only collection.
     *
     * @return all registry values as a read-only collection.
     */
    Collection<V> values();

    /**
     * Returns the value assigned the specified key or throws an {@code IllegalArgumentException} if there is no
     * associated value.  If a value is not required, consider using the {@link #find(Object)} method instead.
     *
     * @param key the registry key assigned to the required value
     * @return the value assigned the specified key
     * @throws IllegalArgumentException if there is no value assigned the specified key
     * @see #find(Object)
     */
    V get(K key) throws IllegalArgumentException;

    /**
     * Returns the value assigned the specified key or {@code null} if there is no associated value.
     *
     * @param key the registry key assigned to the required value
     * @return the value assigned the specified key or {@code null} if there is no associated value.
     * @see #get(Object)
     */
    V find(K key);
}

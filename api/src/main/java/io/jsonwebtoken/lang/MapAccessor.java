/*
 * Copyright (C) 2023 jsonwebtoken.io
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
import java.util.Map;
import java.util.Set;

/**
 * Read operations for a {@link Map} instance.
 *
 * @param <K> map key type
 * @param <V> map value type
 * @since JJWT_RELEASE_VERSION
 */
public interface MapAccessor<K, V> {

    int size();

    boolean isEmpty();

    boolean containsKey(Object key);

    boolean containsValue(Object value);

    V get(Object key);

    Set<K> keySet();

    Collection<V> values();

    Set<Map.Entry<K, V>> entrySet();

    /**
     * Returns a view of the associated Map, which may or may not be mutable.  This is useful for use with existing
     * Map-based APIs, especially if the underlying implementation does not implement the Map interface itself.
     *
     * @return a view of the associated Map, which may or may not be mutable.
     */
    Map<K, V> toMap();
}

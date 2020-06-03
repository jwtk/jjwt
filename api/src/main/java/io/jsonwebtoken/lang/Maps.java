/*
 * Copyright (C) 2019 jsonwebtoken.io
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class to help with the manipulation of working with Maps.
 * @since 0.11.0
 */
public final class Maps {

    private Maps() {} //prevent instantiation

    /**
     * Creates a new map builder with a single entry.
     * <p> Typical usage: <pre>{@code
     * Map<K,V> result = Maps.of("key1", value1)
     *     .and("key2", value2)
     *     // ...
     *     .build();
     * }</pre>
     * @param key the key of an map entry to be added
     * @param value the value of map entry to be added
     * @param <K> the maps key type
     * @param <V> the maps value type
     * Creates a new map builder with a single entry.
     */
    public static <K, V> MapBuilder<K, V> of(K key, V value) {
        return new HashMapBuilder<K, V>().and(key, value);
    }

    /**
     * Utility Builder class for fluently building maps:
     * <p> Typical usage: <pre>{@code
     * Map<K,V> result = Maps.of("key1", value1)
     *     .and("key2", value2)
     *     // ...
     *     .build();
     * }</pre>
     * @param <K> the maps key type
     * @param <V> the maps value type
     */
    public interface MapBuilder<K, V> {
        /**
         * Add a new entry to this map builder
         * @param key the key of an map entry to be added
         * @param value the value of map entry to be added
         * @return the current MapBuilder to allow for method chaining.
         */
        MapBuilder<K, V> and(K key, V value);

        /**
         * Returns a the resulting Map object from this MapBuilder.
         * @return Returns a the resulting Map object from this MapBuilder.
         */
        Map<K, V> build();
    }

    private static class HashMapBuilder<K, V> implements MapBuilder<K, V> {

        private final Map<K, V> data = new HashMap<>();

        public MapBuilder<K, V> and(K key, V value) {
            data.put(key, value);
            return this;
        }
        public Map<K, V> build() {
            return Collections.unmodifiableMap(data);
        }
    }
}

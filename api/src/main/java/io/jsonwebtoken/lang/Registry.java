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

import java.util.Map;

/**
 * An immutable (read-only) repository of key-value pairs. In addition to {@link Map} read methods, this interface also
 * provides guaranteed/expected lookup via the {@link #forKey(Object)} method.
 *
 * <p><b>Immutability</b></p>
 *
 * <p>Registries are immutable and cannot be changed.  {@code Registry} extends the
 * {@link Map} interface purely out of convenience: to allow easy key/value
 * pair access and iteration, and other conveniences provided by the Map interface, as well as for seamless use with
 * existing Map-based APIs.  Attempting to call any of
 * the {@link Map} interface's mutation methods however (such as {@link Map#put(Object, Object) put},
 * {@link Map#remove(Object) remove}, {@link Map#clear() clear}, etc) will throw an
 * {@link UnsupportedOperationException}.</p>
 *
 * @param <K> key type
 * @param <V> value type
 * @since JJWT_RELEASE_VERSION
 */
public interface Registry<K, V> extends Map<K, V> {

    /**
     * Returns the value assigned the specified key or throws an {@code IllegalArgumentException} if there is no
     * associated value.  If a value is not required, consider using the {@link #get(Object)} method instead.
     *
     * @param key the registry key assigned to the required value
     * @return the value assigned the specified key
     * @throws IllegalArgumentException if there is no value assigned the specified key
     * @see #get(Object)
     */
    V forKey(K key) throws IllegalArgumentException;

}

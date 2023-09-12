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

import java.util.Map;
import java.util.Set;

/**
 * A JWK Set is an immutable JSON Object that represents a Set of {@link Jwk}s as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-5">RFC 7517 JWK Set Format</a>. Per that specification,
 * any number of name/value pairs may be present in a {@code JwkSet}, but only a non-empty {@link #getKeys() keys}
 * set <em>MUST</em> be present.
 *
 * <p><b>Immutability</b></p>
 *
 * <p>JWK Sets are immutable and cannot be changed after they are created.  {@code JwkSet} extends the
 * {@link Map} interface purely out of convenience: to allow easy marshalling to JSON as well as name/value
 * pair access and key/value iteration, and other conveniences provided by the Map interface.  Attempting to call any of
 * the {@link Map} interface's mutation methods however (such as {@link Map#put(Object, Object) put},
 * {@link Map#remove(Object) remove}, {@link Map#clear() clear}, etc) will throw an
 * {@link UnsupportedOperationException}.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkSet extends Map<String, Object>, Iterable<Jwk<?>> {

    /**
     * Returns the non-null, non-empty set of JWKs contained within the {@code JwkSet}.
     *
     * @return the non-null, non-empty set of JWKs contained within the {@code JwkSet}.
     */
    Set<Jwk<?>> getKeys();

}

/*
 * Copyright © 2026 jsonwebtoken.io
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

import java.security.Key;

/**
 * Allows setting a key to be used during a cryptographic operation.
 *
 * @param <T> the type of key
 * @param <R> the type of the instance returned, usually used for method chaining.
 * @since JJWT_RELEASE_VERSION
 */
@FunctionalInterface
public interface Keyable<T extends Key, R> {

    /**
     * Sets the key to be used during a cryptographic operation; must be compatible with the target algorithm.
     *
     * @param key the key to use
     * @return the corresponding instance, usually used for method chaining.
     */
    R key(T key);

}

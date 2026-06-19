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

import java.security.SecureRandom;

/**
 * Interface implemented by {@code Object}s that allow configuration of a JCA {@link SecureRandom}.
 *
 * @param <T> the type of {@code Object} returned after setting the {@code SecureRandom}, usually for method chaining.
 * @since JJWT_RELEASE_VERSION
 */
@FunctionalInterface
public interface Randomizable<T> {

    /**
     * Sets the JCA {@link SecureRandom} to use during cryptographic operations.  This is an optional property -
     * if not specified, a default {@code SecureRandom} will be used if necessary.
     *
     * @param random the JCA {@code SecureRandom} instance to use during cryptographic operations.
     * @return the associated object for method chaining.
     */
    T random(SecureRandom random);
}

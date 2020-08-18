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
package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PbeKeyBuilder<K extends PbeKey> {

    /**
     * Sets the password character array for the constructed key.  This does not clone the argument - changes made
     * to the backing array will be reflected by the constructed key and any {@link PbeKey#destroy()} call will do
     * the same. This is to ensure that any clearing of the password argument for security/safety reasons also
     * guarantees the resulting key is also cleared and vice versa.
     *
     * @param password password character array for the constructed key
     * @return this builder for method chaining
     */
    PbeKeyBuilder<K> setPassword(char[] password);

    /**
     * Sets the number of hashing iterations to perform when deriving an encryption key.
     *
     * @param iterations the number of hashing iterations to perform when deriving an encryption key.
     * @return @return this builder for method chaining
     */
    PbeKeyBuilder<K> setIterations(int iterations);

    /**
     * Constructs a new {@link PbeKey} that shares the {@link #setPassword(char[]) specified} password character array.
     * Changes to that char array will be reflected in the returned key, and similarly,
     * any call to the key's {@link PbeKey#destroy() destroy} method will clear/overwrite the shared char array.
     * This is to ensure that any clearing of the password char array for security/safety reasons also
     * guarantees the key is also cleared and vice versa.
     *
     * @return a new {@link PbeKey} that shares the {@link #setPassword(char[]) specified} password character array.
     */
    K build();
}

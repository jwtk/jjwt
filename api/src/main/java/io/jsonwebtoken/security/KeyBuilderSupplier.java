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

import java.security.Key;

/**
 * Interface implemented by components that support building/creating new {@link Key}s suitable for use with
 * their associated cryptographic algorithm implementation.
 *
 * @param <K> type of {@link Key} created by the builder
 * @param <B> type of builder to create each time {@link #key()} is called.
 * @see #key()
 * @see KeyBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyBuilderSupplier<K extends Key, B extends KeyBuilder<K, B>> {

    /**
     * Returns a new {@link KeyBuilder} instance that will produce new secure-random keys with a length sufficient
     * to be used by the component's associated cryptographic algorithm.
     *
     * @return a new {@link KeyBuilder} instance that will produce new secure-random keys with a length sufficient
     * to be used by the component's associated cryptographic algorithm.
     */
    B key();
}

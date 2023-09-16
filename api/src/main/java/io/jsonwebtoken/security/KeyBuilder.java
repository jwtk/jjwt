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

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code KeyBuilder} produces new {@link Key}s suitable for use with an associated cryptographic algorithm.
 * A new {@link Key} is created each time the builder's {@link #build()} method is called.
 *
 * <p>{@code KeyBuilder}s are provided by components that implement the {@link KeyBuilderSupplier} interface,
 * ensuring the resulting {@link SecretKey}s are compatible with their associated cryptographic algorithm.</p>
 *
 * @param <K> the type of key to build
 * @param <B> the type of the builder, for subtype method chaining
 * @see KeyBuilderSupplier
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyBuilder<K extends Key, B extends KeyBuilder<K, B>> extends SecurityBuilder<K, B> {
}

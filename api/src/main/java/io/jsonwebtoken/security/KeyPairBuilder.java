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

import java.security.KeyPair;

/**
 * A {@code KeyPairBuilder} produces new {@link KeyPair}s suitable for use with an associated cryptographic algorithm.
 * A new {@link KeyPair} is created each time the builder's {@link #build()} method is called.
 *
 * <p>{@code KeyPairBuilder}s are provided by components that implement the {@link KeyPairBuilderSupplier} interface,
 * ensuring the resulting {@link KeyPair}s are compatible with their associated cryptographic algorithm.</p>
 *
 * @see KeyPairBuilderSupplier
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPairBuilder extends SecurityBuilder<KeyPair, KeyPairBuilder> {
}

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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * An {@link AsymmetricJwkBuilder} that creates {@link PublicJwk} instances.
 *
 * @param <K> the type of {@link PublicKey} provided by the created public JWK.
 * @param <L> the type of {@link PrivateKey} that may be paired with the {@link PublicKey} to produce a {@link PrivateJwk} if desired.
 * @param <J> the type of {@link PublicJwk} created
 * @param <M> the type of {@link PrivateJwk} that matches the created {@link PublicJwk}
 * @param <P> the type of {@link PrivateJwkBuilder} that matches this builder if a {@link PrivateJwk} is desired.
 * @param <T> the type of the builder, for subtype method chaining
 * @see #privateKey(PrivateKey)
 * @since JJWT_RELEASE_VERSION
 */
public interface PublicJwkBuilder<K extends PublicKey, L extends PrivateKey,
        J extends PublicJwk<K>, M extends PrivateJwk<L, K, J>,
        P extends PrivateJwkBuilder<L, K, J, M, P>,
        T extends PublicJwkBuilder<K, L, J, M, P, T>> extends AsymmetricJwkBuilder<K, J, T> {

    /**
     * Sets the {@link PrivateKey} that pairs with the builder's existing {@link PublicKey}, converting this builder
     * into a {@link PrivateJwkBuilder} which will produce a corresponding {@link PrivateJwk} instance.  The
     * specified {@code privateKey} <em>MUST</em> be the exact private key paired with the builder's public key.
     *
     * @param privateKey the {@link PrivateKey} that pairs with the builder's existing {@link PublicKey}
     * @return the builder coerced as a {@link PrivateJwkBuilder} which will produce a corresponding {@link PrivateJwk}.
     */
    P privateKey(L privateKey);
}

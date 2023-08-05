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
 * An {@link AsymmetricJwkBuilder} that creates {@link PrivateJwk} instances.
 *
 * @param <K> the type of Java {@link PrivateKey} provided by the created private JWK.
 * @param <L> the type of Java {@link PublicKey} paired with the private key.
 * @param <M> the type of {@link PrivateJwk} created
 * @param <J> the type of {@link PublicJwk} paired with the created private JWK.
 * @param <T> the type of the builder, for subtype method chaining
 * @see #publicKey(PublicKey)
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateJwkBuilder<K extends PrivateKey, L extends PublicKey,
        J extends PublicJwk<L>, M extends PrivateJwk<K, L, J>,
        T extends PrivateJwkBuilder<K, L, J, M, T>> extends AsymmetricJwkBuilder<K, M, T> {

    /**
     * Allows specifying of the {@link PublicKey} associated with the builder's existing {@link PrivateKey},
     * offering a reasonable performance enhancement when building the final private JWK.  Application developers
     * should prefer to use this method when possible when building private JWKs.
     *
     * <p>As discussed in the {@link PrivateJwk} documentation, the JWK and JWA specifications require private JWKs to
     * contain <em>both</em> private key <em>and</em> public key data.  If a public key is not provided via this
     * {@code publicKey} method, the builder implementation must go through the work to derive the
     * {@code PublicKey} instance based on the {@code PrivateKey} to obtain the necessary public key information.</p>
     *
     * <p>Calling this method with the {@code PrivateKey}'s matching {@code PublicKey} instance eliminates the need
     * for the builder to do that work.</p>
     *
     * @param publicKey the {@link PublicKey} that matches the builder's existing {@link PrivateKey}.
     * @return the builder for method chaining.
     */
    T publicKey(L publicKey);
}

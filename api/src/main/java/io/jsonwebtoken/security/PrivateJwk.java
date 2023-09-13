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
 * JWK representation of a {@link PrivateKey}.
 *
 * <p><b>JWK Private Key vs Java {@code PrivateKey} differences</b></p>
 *
 * <p>Unlike the Java cryptography APIs, the JWK specification requires all public key <em>and</em> private key
 * properties to be contained within every private JWK. As such, a {@code PrivateJwk} indeed represents
 * private key values as its name implies, but it is probably more similar to the Java JCA concept of a
 * {@link java.security.KeyPair} since it contains everything for both keys.</p>
 *
 * <p>Consequently a {@code PrivateJwk} is capable of providing two additional convenience methods:</p>
 * <ul>
 *     <li>{@link #toPublicJwk()} - a method to obtain a {@link PublicJwk} instance that contains only the JWK public
 *     key properties, and</li>
 *     <li>{@link #toKeyPair()} - a method to obtain both Java {@link PublicKey} and {@link PrivateKey}s in aggregate
 *     as a {@link KeyPair} instance if desired.</li>
 * </ul>
 *
 * @param <K> The type of {@link PrivateKey} represented by this JWK
 * @param <L> The type of {@link PublicKey} represented by the JWK's corresponding {@link #toPublicJwk() public JWK}.
 * @param <M> The type of {@link PublicJwk} reflected by the JWK's public properties.
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateJwk<K extends PrivateKey, L extends PublicKey, M extends PublicJwk<L>> extends AsymmetricJwk<K> {

    /**
     * Returns the private JWK's corresponding {@link PublicJwk}, containing only the key's public properties.
     *
     * @return the private JWK's corresponding {@link PublicJwk}, containing only the key's public properties.
     */
    M toPublicJwk();

    /**
     * Returns the key's corresponding Java {@link PrivateKey} and {@link PublicKey} in aggregate as a
     * type-safe {@link KeyPair} instance.
     *
     * @return the key's corresponding Java {@link PrivateKey} and {@link PublicKey} in aggregate as a
     * type-safe {@link KeyPair} instance.
     */
    KeyPair<L, K> toKeyPair();
}

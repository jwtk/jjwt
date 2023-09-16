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
 * Generics-capable and type-safe alternative to {@link java.security.KeyPair}.  Instances may be
 * converted to {@link java.security.KeyPair} if desired via {@link #toJavaKeyPair()}.
 *
 * @param <A> The type of {@link PublicKey} in the key pair.
 * @param <B> The type of {@link PrivateKey} in the key pair.
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPair<A extends PublicKey, B extends PrivateKey> {

    /**
     * Returns the pair's public key.
     *
     * @return the pair's public key.
     */
    A getPublic();

    /**
     * Returns the pair's private key.
     *
     * @return the pair's private key.
     */
    B getPrivate();

    /**
     * Returns this instance as a {@link java.security.KeyPair} instance.
     *
     * @return this instance as a {@link java.security.KeyPair} instance.
     */
    java.security.KeyPair toJavaKeyPair();
}

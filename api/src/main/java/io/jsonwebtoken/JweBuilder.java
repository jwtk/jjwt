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
package io.jsonwebtoken;

import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code JwtBuilder} that creates JWEs.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JweBuilder extends JwtBuilder<JweBuilder> {

    /**
     * Encrypts the constructed JWT with the specified {@link AeadAlgorithm} Content Encryption Algorithm.  The
     * key used to perform the encryption must be supplied by calling {@link #withKey(SecretKey)} or
     * {@link #withKeyFrom(Key, KeyAlgorithm)}.
     *
     * @param enc the {@link AeadAlgorithm} algorithm used to encrypt the JWE.
     * @return the builder for method chaining.
     */
    JweBuilder encryptWith(AeadAlgorithm enc);

    /**
     * Specifies the shared symmetric key to use to encrypt the JWE using the AEAD content encryption algorithm
     * specified via the {@link #encryptWith(AeadAlgorithm)} builder method.
     *
     * <p>This is a convenience method that is an alias for the following:</p>
     *
     * <blockquote><pre>
     * {@link #withKeyFrom(Key, KeyAlgorithm) withKeyFrom}(key, {@link io.jsonwebtoken.security.KeyAlgorithms KeyAlgorithms}.{@link io.jsonwebtoken.security.KeyAlgorithms#DIRECT DIRECT});</pre></blockquote>
     *
     * @param key the shared symmetric key to use to encrypt the JWE.
     * @return the builder for method chaining.
     */
    JweBuilder withKey(SecretKey key);

    /**
     * Use the specified {@code key} to invoke the specified {@link KeyAlgorithm} to obtain a
     * {@code Content Encryption Key (CEK)}.  The resulting CEK will be used to encrypt the JWE using the
     * AEAD content encryption algorithm specified via the {@link #encryptWith(AeadAlgorithm)} builder method.
     *
     * @param key    the key to use with the {@code keyAlg} to obtain a {@code Content Encryption Key (CEK)}.
     * @param keyAlg the key algorithm that will provide a {@code Content Encryption Key (CEK)}.
     * @param <K>    the type of key to use with {@code keyAlg}
     * @return the builder for method chaining.
     */
    <K extends Key> JweBuilder withKeyFrom(K key, KeyAlgorithm<K, ?> keyAlg);
}

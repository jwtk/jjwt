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
import io.jsonwebtoken.security.KeyAlgorithms;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code JwtBuilder} that creates JWEs.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JweBuilder extends JwtBuilder<JweBuilder> {

    /**
     * Encrypts the constructed JWT with the specified {@code enc}ryption algorithm using the provided
     * symmetric {@code key}.  Because it is a symmetric key, the party decrypting the resulting
     * JWE must also have access to the same key.
     *
     * <p>This method is a convenience method that delegates to
     * {@link #encryptWith(AeadAlgorithm, Key, KeyAlgorithm) encryptWith(enc, key, KeyAlgorithm)}
     * based on the {@code key} argument:</p>
     * <ul>
     *     <li>If the provided {@code key} is an instance of {@link io.jsonwebtoken.security.PasswordKey PasswordKey},
     *     the {@code KeyAlgorithm} used will be one of the three JWA-standard password-based key algorithms
     *      ({@link KeyAlgorithms#PBES2_HS256_A128KW PBES2_HS256_A128KW},
     *      {@link KeyAlgorithms#PBES2_HS384_A192KW PBES2_HS384_A192KW}, or
     *      {@link KeyAlgorithms#PBES2_HS512_A256KW PBES2_HS512_A256KW}) as determined by the {@code enc} algorithm's
     *      {@link AeadAlgorithm#getKeyBitLength() key length} requirement.</li>
     *     <li>If the {@code key} is otherwise a standard {@code SecretKey}, the {@code KeyAlgorithm} will be
     *     {@link KeyAlgorithms#DIRECT}, indicating that {@code key} should be used directly with the
     *     {@code enc} algorithm.  In this case, the {@code key} argument <em>MUST</em> be of sufficient strength to
     *     use with the specified {@code enc} algorithm, otherwise an exception will be thrown during encryption. If
     *     desired, secure-random keys suitable for an {@link AeadAlgorithm} may be generated using the algorithm's
     *     {@link AeadAlgorithm#keyBuilder() keyBuilder}.</li>
     * </ul>
     *
     * @param enc the {@link AeadAlgorithm} algorithm used to encrypt the JWE.
     * @param key the symmetric encryption key to use with the {@code enc} algorithm.
     * @return the JWE builder for method chaining.
     */
    JweBuilder encryptWith(AeadAlgorithm enc, SecretKey key);

    /**
     * Encrypts the constructed JWT with the specified {@code enc} algorithm using the symmetric key produced by
     * the {@code keyAlg} when invoked with the specified {@code key}.  In other words, the {@code keyAlg} is first
     * invoked with the specified {@code key}, and that produces a {@link SecretKey} result.  This resulting
     * {@code SecretKey} is then used with the {@code enc} algorithm to encrypt the JWE.
     *
     * <p>The {@link KeyAlgorithms} utility class makes available all Key Algorithms defined by the JWA
     * specification.</p>
     *
     * @param enc    the {@link AeadAlgorithm} used to encrypt the JWE.
     * @param key    the key used to call the provided {@code keyAlg} instance.
     * @param keyAlg the key management algorithm that will produce the symmetric {@code SecretKey} to use with the
     *               {@code enc} algorithm.
     * @param <K>    the type of key that must be used with the specified {@code keyAlg} instance.
     * @return the JWE builder for method chaining.
     */
    <K extends Key> JweBuilder encryptWith(AeadAlgorithm enc, K key, KeyAlgorithm<K, ?> keyAlg);
}

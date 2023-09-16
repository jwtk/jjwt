/*
 * Copyright © 2022 jsonwebtoken.io
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

import io.jsonwebtoken.Identifiable;

import javax.crypto.SecretKey;

/**
 * A {@link SecureDigestAlgorithm} that uses symmetric {@link SecretKey}s to both compute and verify digests as
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message authentication codes</a> (MACs).
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code MacAlgorithm} extends {@link Identifiable}: when a {@code MacAlgorithm} is used to compute the MAC of a
 * JWS, the value returned from {@link Identifiable#getId() macAlgorithm.getId()} will be set as the JWS
 * <code>&quot;alg&quot;</code> protected header value.</p>
 *
 * <p><b>Key Strength</b></p>
 *
 * <p>MAC algorithm strength is in part attributed to how difficult it is to discover the secret key.
 * As such, MAC algorithms usually require keys of a minimum length to ensure the keys are difficult to discover
 * and the algorithm's security properties are maintained.</p>
 *
 * <p>The {@code MacAlgorithm} interface extends the {@link KeyLengthSupplier} interface to represent
 * the length in bits (<em>not bytes</em>) a key must have to be used with its implementation.  If you do not want to
 * worry about lengths and parameters of keys required for an algorithm, it is often easier to automatically generate
 * a key that adheres to the algorithms requirements, as discussed below.</p>
 *
 * <p><b>Key Generation</b></p>
 *
 * <p>{@code MacAlgorithm} extends {@link KeyBuilderSupplier} to enable {@link SecretKey} generation.
 * Each {@code MacAlgorithm} algorithm instance will return a {@link KeyBuilder} that ensures any created keys will
 * have a sufficient length and any algorithm parameters required by that algorithm. For example:</p>
 *
 * <blockquote><pre>
 * SecretKey key = macAlgorithm.key().build();</pre></blockquote>
 *
 * <p>The resulting {@code key} is guaranteed to have the correct algorithm parameters and strength/length necessary for
 * that exact {@code MacAlgorithm} instance.</p>
 *
 * <p><b>JWA Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all JWA (RFC 7518) standard MAC algorithms are
 * available via {@link io.jsonwebtoken.Jwts.SIG Jwts.SIG}.</p>
 *
 * @see io.jsonwebtoken.Jwts.SIG Jwts.SIG
 * @since JJWT_RELEASE_VERSION
 */
public interface MacAlgorithm extends SecureDigestAlgorithm<SecretKey, SecretKey>,
        KeyBuilderSupplier<SecretKey, SecretKeyBuilder>, KeyLengthSupplier {
}

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

import io.jsonwebtoken.Identifiable;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> algorithm computes and
 * verifies digests using asymmetric public/private key cryptography.
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code SignatureAlgorithm} extends {@link Identifiable}: when a {@code SignatureAlgorithm} is used to compute
 * a JWS digital signature, the value returned from {@link Identifiable#getId() signatureAlgorithm.getId()} will be
 * set as the JWS <code>&quot;alg&quot;</code> protected header value.</p>
 *
 * <p><b>Key Pair Generation</b></p>
 *
 * <p>{@code SignatureAlgorithm} extends {@link KeyPairBuilderSupplier} to enable
 * {@link KeyPair} generation. Each {@code SignatureAlgorithm} instance will return a
 * {@link KeyPairBuilder} that ensures any created key pairs will have a sufficient length and algorithm parameters
 * required by that algorithm.  For example:</p>
 *
 * <blockquote><pre>
 * KeyPair pair = signatureAlgorithm.keyPair().build();</pre></blockquote>
 *
 * <p>The resulting {@code pair} is guaranteed to have the correct algorithm parameters and length/strength necessary
 * for that exact {@code signatureAlgorithm} instance.</p>
 *
 * <p><b>JWA Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all JWA (RFC 7518) standard signature algorithms are
 * available via {@link io.jsonwebtoken.Jwts.SIG Jwts.SIG}.</p>
 *
 * @see io.jsonwebtoken.Jwts.SIG Jwts.SIG
 * @since JJWT_RELEASE_VERSION
 */
public interface SignatureAlgorithm extends SecureDigestAlgorithm<PrivateKey, PublicKey>, KeyPairBuilderSupplier {
}

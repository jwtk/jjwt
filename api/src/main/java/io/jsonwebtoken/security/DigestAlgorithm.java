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
import io.jsonwebtoken.lang.Registry;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A {@code DigestAlgorithm} is a
 * <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function">Cryptographic Hash Function</a>
 * that computes and verifies cryptographic digests.  There are three types of {@code DigestAlgorithm}s represented
 * by subtypes, and RFC-standard implementations are available as constants in {@link Registry} singletons:
 *
 * <table>
 *     <caption>Types of {@code DigestAlgorithm}s</caption>
 *     <thead>
 *         <tr>
 *             <th>Subtype</th>
 *             <th>Standard Implementation Registry</th>
 *             <th>Security Model</th>
 *         </tr>
 *     </thead>
 *     <tbody>
 *         <tr>
 *             <td>{@link HashAlgorithm}</td>
 *             <td>{@link Jwks.HASH}</td>
 *             <td>Unsecured (unkeyed), does not require a key to compute or verify digests.</td>
 *         </tr>
 *         <tr>
 *             <td>{@link MacAlgorithm}</td>
 *             <td>{@link io.jsonwebtoken.Jwts.SIG Jwts.SIG}</td>
 *             <td>Requires a {@link SecretKey} to both compute and verify digests (aka
 *                 &quot;Message Authentication Codes&quot;).</td>
 *         </tr>
 *         <tr>
 *             <td>{@link SignatureAlgorithm}</td>
 *             <td>{@link io.jsonwebtoken.Jwts.SIG Jwts.SIG}</td>
 *             <td>Requires a {@link PrivateKey} to compute and {@link PublicKey} to verify digests
 *                 (aka &quot;Digital Signatures&quot;).</td>
 *         </tr>
 *     </tbody>
 * </table>
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code DigestAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWT standard identifier where required.</p>
 *
 * <p>For example,
 * when a {@link MacAlgorithm} or {@link SignatureAlgorithm} is used to secure a JWS, the value returned from
 * {@code algorithm.getId()} will be used as the JWS <code>&quot;alg&quot;</code> protected header value.  Or when a
 * {@link HashAlgorithm} is used to compute a {@link JwkThumbprint}, it's {@code algorithm.getId()} value will be
 * used within the thumbprint's {@link JwkThumbprint#toURI() URI} per JWT RFC requirements.</p>
 *
 * @param <R> the type of {@link Request} used when computing a digest.
 * @param <V> the type of {@link VerifyDigestRequest} used when verifying a digest.
 * @see Jwks.HASH
 * @see io.jsonwebtoken.Jwts.SIG Jwts.SIG
 * @since JJWT_RELEASE_VERSION
 */
public interface DigestAlgorithm<R extends Request<byte[]>, V extends VerifyDigestRequest> extends Identifiable {

    /**
     * Returns a cryptographic digest of the request {@link Request#getPayload() payload}.
     *
     * @param request the request containing the data to be hashed, mac'd or signed.
     * @return a cryptographic digest of the request {@link Request#getPayload() payload}.
     * @throws SecurityException if there is invalid key input or a problem during digest creation.
     */
    byte[] digest(R request) throws SecurityException;

    /**
     * Returns {@code true} if the provided {@link VerifyDigestRequest#getDigest() digest} matches the expected value
     * for the given {@link VerifyDigestRequest#getPayload() payload}, {@code false} otherwise.
     *
     * @param request the request containing the {@link VerifyDigestRequest#getDigest() digest} to verify for the
     *                associated {@link VerifyDigestRequest#getPayload() payload}.
     * @return {@code true} if the provided {@link VerifyDigestRequest#getDigest() digest} matches the expected value
     * for the given {@link VerifyDigestRequest#getPayload() payload}, {@code false} otherwise.
     * @throws SecurityException if there is an invalid key input or a problem that won't allow digest verification.
     */
    boolean verify(V request) throws SecurityException;
}

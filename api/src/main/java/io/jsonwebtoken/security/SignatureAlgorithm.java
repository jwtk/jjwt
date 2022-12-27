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

import java.security.Key;

/**
 * A cryptographic algorithm that computes and verifies the authenticity of data via
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signatures</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication codes</a> as defined by the
 * <a href="https://www.rfc-editor.org/rfc/rfc7515.html">JSON Web Signature (JWS)</a> specification.
 *
 * <p><b>Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all standard
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">JWA (RFC 7518) Signature Algorithms</a> are
 * available via the {@link SignatureAlgorithms} utility class.</p>
 *
 * <p><b>&quot;alg&quot; identifier</b></p>
 *
 * <p>{@code SignatureAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWS &quot;alg&quot; protected header value.</p>
 *
 * @param <S> the type of {@link Key} used to create digital signatures or message authentication codes
 * @param <V> the type of {@link Key} used to verify digital signatures or message authentication codes
 * @since JJWT_RELEASE_VERSION
 */
public interface SignatureAlgorithm<S extends Key, V extends Key> extends Identifiable {

    /**
     * Compute a digital signature or MAC for the request {@link SignatureRequest#getContent() content} using the
     * request {@link SignatureRequest#getKey() key}, returning the digest result.
     *
     * @param request the signature request representing the plaintext data to be signed or MAC'd and the
     *                {@code key} used during execution.
     * @return the resulting digital signature or MAC.
     * @throws SecurityException if there is invalid key input or a problem during digest creation.
     */
    byte[] sign(SignatureRequest<S> request) throws SecurityException;

    /**
     * Verify the authenticity of the previously computed digital signature or MAC
     * {@link VerifySignatureRequest#getDigest() digest output} represented by the specified  {@code request}.
     *
     * @param request the request representing the previously-computed digital signature or MAC
     *                {@link VerifySignatureRequest#getDigest() digest output}, original
     *                {@link VerifySignatureRequest#getContent() content} and
     *                {@link VerifySignatureRequest#getKey() verification key}.
     * @return {@code true} if the authenticity and integrity of the previously-computed digital signature or MAC can
     * be verified, {@code false} otherwise.
     * @throws SecurityException if there is invalid key input or a problem that won't allow digest verification.
     */
    boolean verify(VerifySignatureRequest<V> request) throws SecurityException;
}

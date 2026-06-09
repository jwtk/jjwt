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
import io.jsonwebtoken.lang.Assert;

import java.io.InputStream;
import java.security.Key;
import java.util.function.Consumer;

/**
 * A {@link DigestAlgorithm} that requires a {@link Key} to compute and verify the authenticity of digests using either
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication code</a> algorithms.
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code SecureDigestAlgorithm} extends {@link Identifiable}: when a {@code SecureDigestAlgorithm} is used to
 * compute the digital signature or MAC of a JWS, the value returned from
 * {@link Identifiable#getId() secureDigestAlgorithm.getId()} will be set as the JWS
 * <code>&quot;alg&quot;</code> protected header value.</p>
 *
 * <p><b>Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all JWA (RFC 7518) standard
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic Algorithms for Digital Signatures and
 * MACs</a> are available via {@link io.jsonwebtoken.Jwts.SIG Jwts.SIG}.</p>
 *
 * <p><b>&quot;alg&quot; identifier</b></p>
 *
 * <p>{@code SecureDigestAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWS &quot;alg&quot; protected header value.</p>
 *
 * @param <S> the type of {@link Key} used to create digital signatures or message authentication codes
 * @param <V> the type of {@link Key} used to verify digital signatures or message authentication codes
 * @see MacAlgorithm
 * @see SignatureAlgorithm
 * @since 0.12.0
 */
public interface SecureDigestAlgorithm<S extends Key, V extends Key>
        extends DigestAlgorithm<SecureRequest<InputStream, S>, VerifySecureDigestRequest<V>> {

    /**
     * Computes a mac or signature of an {@link InputStream} using named parameters. At least the
     * {@link SecureRequest#getPayload() payload} and mac or signing {@link SecureRequest#getKey() key} parameters
     * must be specified. For example:
     *
     * <p><code>
     * alg.digest(r -&gt; r.{@link SecureRequest.Params#payload(Object) payload}(is).{@link SecureRequest.Params#key(Key) key}(key));
     * </code></p>
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the
     * payload {@code InputStream} if necessary after calling this method.</p>
     *
     * @param c consumer supporting lambda-style specification of named digest {@link SecureRequest.Params}.
     * @return the computed mac or signature for the request {@link SecureRequest#getPayload() payload}.
     * @since JJWT_RELEASE_VERSION
     */
    default byte[] digest(Consumer<SecureRequest.Params<InputStream, S, ?>> c) {
        Assert.notNull(c, "Consumer cannot be null");
        SecureRequest.Builder<InputStream, S> b = SecureRequest.builder();
        c.accept(b);
        SecureRequest<InputStream, S> r = b.build();
        return digest(r);
    }

    /**
     * Computes a mac or signature of the specified {@code is} input stream using the specified {@code key}. This is
     * a convenience method equivalent to:
     *
     * <p><code>
     * {@link #digest(Request) digest}(r -&gt; r.{@link SecureRequest.Params#payload(Object) payload}(is).{@link SecureRequest.Params#key(Key) key}(key));
     * </code></p>
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the
     * {@code is} input stream if necessary after calling this method.</p>
     *
     * @param key the key used to compute the mac or signature
     * @param is  the {@code InputStream} that will be consumed to compute the mac or signature. Callers are expected to
     *            {@link InputStream#close() close} or {@link InputStream#reset() reset} the {@code is} input stream if
     *            necessary after calling this method.
     * @return the computed mac or signature of the specified {@code is} input stream.
     * @since JJWT_RELEASE_VERSION
     */
    default byte[] digest(S key, InputStream is) {
        return digest(c -> c.payload(is).key(key));
    }

    /**
     * Returns {@code true} if a given mac or signature for an {@link InputStream} is authentic, {@code false}
     * otherwise. At least the {@link VerifySecureDigestRequest#getPayload() payload} stream, verification
     * {@link VerifySecureDigestRequest#getKey() key}, and {@link VerifySecureDigestRequest#getDigest() digest}
     * parameters must be specified. For example:
     *
     * <p><code>
     * alg.verify(r -&gt; r.{@link VerifySecureDigestRequest.Params#key(Key) key}(key).{@link VerifySecureDigestRequest.Params#payload(Object) payload}(is).{@link VerifySecureDigestRequest.Params#digest(byte[]) digest}(macOrSignature));
     * </code></p>
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the request
     * payload stream if necessary after calling this method.</p>
     *
     * @param c consumer supporting lambda-style specification of named {@link VerifySecureDigestRequest.Params}.
     * @return {@code true} if a given mac or signature for an {@code InputStream} is authentic, {@code false} otherwise.
     * @since JJWT_RELEASE_VERSION
     */
    default boolean verify(Consumer<VerifySecureDigestRequest.Params<V, ?>> c) {
        Assert.notNull(c, "Consumer cannot be null");
        VerifySecureDigestRequest.Builder<V> b = VerifySecureDigestRequest.builder();
        c.accept(b);
        VerifySecureDigestRequest<V> r = b.build();
        return verify(r);
    }

    /**
     * Returns {@code true} if the given {@code macOrSignature} for the {@code is} input stream is
     * authentic, {@code false} otherwise. This is a convenience method equivalent to:
     *
     * <p><code>
     * {@link #verify(VerifyDigestRequest) verify}(r -&gt; r.{@link VerifySecureDigestRequest.Params#key(Key) key}(key).{@link VerifySecureDigestRequest.Params#payload(Object) payload}(is).{@link VerifySecureDigestRequest.Params#digest(byte[]) digest}(macOrSignature));
     * </code></p>
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the
     * {@code is} input stream if necessary after calling this method.</p>
     *
     * @param key            the key used to verify the mac or signature
     * @param is             the data claimed as authentic by {@code macOrSignature}, which will be consumed to
     *                       verify authenticity. Callers are expected to {@link InputStream#close() close} or
     *                       {@link InputStream#reset() reset} this stream if necessary after calling this method.
     * @param macOrSignature the mac or signature claimed to authenticate the {@code is} input stream.
     * @return {@code true} if the given {@code macOrSignature} for the {@code is} input stream is authentic,
     * {@code false} otherwise.
     * @since JJWT_RELEASE_VERSION
     */
    default boolean verify(V key, InputStream is, byte[] macOrSignature) {
        return verify(c -> c.payload(is).key(key).digest(macOrSignature));
    }
}

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
import java.util.function.Consumer;

/**
 * A {@link DigestAlgorithm} that computes and verifies digests without the use of a cryptographic key, such as for
 * thumbprints and <a href="https://en.wikipedia.org/wiki/Fingerprint_(computing)">digital fingerprint</a>s.
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code HashAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} in all JWT standard hash algorithms will return one of the
 * &quot;{@code Hash Name String}&quot; values defined in the IANA
 * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">Named Information Hash
 * Algorithm Registry</a>. This is to ensure the correct algorithm ID is used within other JWT-standard identifiers,
 * such as within <a href="https://www.rfc-editor.org/rfc/rfc9278.html">JWK Thumbprint URI</a>s.</p>
 *
 * <p><b>IANA Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for common (<em>but not all</em>)
 * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
 * Algorithms</a> are available via {@link Jwks.HASH}.</p>
 *
 * @see Jwks.HASH
 * @since 0.12.0
 */
public interface HashAlgorithm extends DigestAlgorithm<Request<InputStream>, VerifyDigestRequest> {

    /**
     * Computes a digest of a request {@link Request#getPayload() payload} {@code InputStream} or byte array using
     * configured parameters. This is a lambda-style method to execute the request in-line instead of requiring the
     * caller to first use a {@link DigestRequest.Builder} to construct the request.
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} any specified
     * request payload {@code InputStream} if necessary after calling this method.</p>
     *
     * @param p lambda-style consumer for specifying digest algorithm {@link DigestAlgorithm.Params parameters}.
     * @return the computed digest of the request {@link DigestRequest#getPayload() payload}.
     * @since JJWT_RELEASE_VERSION
     */
    default byte[] digest(Consumer<DigestAlgorithm.Params<?>> p) {
        Assert.notNull(p, "Consumer cannot be null");
        DigestRequest.Builder b = DigestRequest.builder();
        p.accept(b);
        DigestRequest r = b.build();
        return digest(r);
    }

    /**
     * Computes a hash of the specified {@code is} input stream.  This is a convenience method using the algorithm
     * default JCA provider and {@code SecureRandom}, and is equivalent to:
     * <blockquote><pre>
     * return digest(r -&gt; r.payload(is));</pre></blockquote>
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the payload
     * stream if necessary after calling this method.</p>
     *
     * @param is the {@code InputStream} that will be consumed to compute the digest. Callers are expected to
     *           {@link InputStream#close() close} or {@link InputStream#reset() reset} the payload stream if necessary
     *           after calling this method.
     * @return the computed digest of the specified {@code is} input stream.
     * @since JJWT_RELEASE_VERSION
     */
    default byte[] digest(InputStream is) {
        return digest(r -> r.payload(is));
    }

    /**
     * Computes a hash of the specified byte array. This is a convenience method using the algorithm default JCA
     * provider and {@code SecureRandom}, and is equivalent to:
     * <blockquote><pre>
     * return digest(r -&gt; r.payload(payload));</pre></blockquote>
     *
     * @param payload the byte array to hash
     * @return the computed hash (aka digest) of the specified byte array.
     * @since JJWT_RELEASE_VERSION
     */
    default byte[] digest(byte[] payload) {
        return digest(r -> r.payload(payload));
    }

    /**
     * Returns {@code true} if the request's specified {@link VerifyDigestRequest#getDigest() digest} matches (equals)
     * the algorithm's computed digest of the request {@link VerifyDigestRequest#getPayload() payload}, {@code false}
     * otherwise. This is a lambda-style method to execute the request in-line instead of requiring the caller to first
     * use a {@link VerifyDigestRequest.Builder} to construct the request.
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the request
     * payload stream if necessary after calling this method.</p>
     *
     * @param p params consumer supporting lambda-style specification of {@link DigestAlgorithm.VerifyParams}.
     * @return {@code true} if the request's specified {@link VerifyDigestRequest#getDigest() digest} matches (equals)
     * the algorithm's computed digest of the request {@link VerifyDigestRequest#getPayload() payload}, {@code false}
     * otherwise.
     * @since JJWT_RELEASE_VERSION
     */
    default boolean verify(Consumer<DigestAlgorithm.VerifyParams<?>> p) {
        Assert.notNull(p, "Consumer cannot be null");
        VerifyDigestRequest.Builder b = VerifyDigestRequest.builder();
        p.accept(b);
        VerifyDigestRequest r = b.build();
        return verify(r);
    }

    /**
     * Returns {@code true} if the specified {@code digest} matches (equals) the algorithm's computed digest of the
     * specified {@code is} input stream, {@code false} otherwise.
     *
     * <p>Callers are expected to {@link InputStream#close() close} or {@link InputStream#reset() reset} the payload
     * stream if necessary after calling this method.</p>
     *
     * @param is     the {@code InputStream} that will be consumed to compute the digest. Callers are expected to
     *               {@link InputStream#close() close} or {@link InputStream#reset() reset} the payload stream if
     *               necessary after calling this method.
     * @param digest the previously computed digest to compare with the algorithm's computed digest of {@code is}.
     * @return {@code true} if the specified {@code digest} matches (equals) the algorithm's computed digest of the
     * specified {@code is} input stream, {@code false} otherwise.
     * @since JJWT_RELEASE_VERSION
     */
    default boolean verify(InputStream is, byte[] digest) {
        return verify(c -> c.payload(is).digest(digest));
    }

    /**
     * Returns {@code true} if the specified {@code digest} matches (equals) the algorithm's computed digest of the
     * specified {@code payload} byte array, {@code false} otherwise.
     *
     * @param payload the byte array to hash
     * @param digest  the previously computed digest to compare with the algorithm's computed digest of {@code payload}.
     * @return {@code true} if the specified {@code digest} matches (equals) the algorithm's computed digest of the
     * specified {@code payload}, {@code false} otherwise.
     * @since JJWT_RELEASE_VERSION
     */
    default boolean verify(byte[] payload, byte[] digest) {
        return verify(c -> c.payload(payload).digest(digest));
    }
}

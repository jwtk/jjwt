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

    default byte[] digest(Consumer<Request.Params<InputStream, ?>> c) {
        Request.Builder<InputStream> b = Request.builder();
        c.accept(b);
        Request<InputStream> r = b.build();
        return digest(r);
    }

    default byte[] digest(InputStream is) {
        return digest(c -> c.payload(is));
    }

    default boolean verify(Consumer<VerifyDigestRequest.Params<?>> c) {
        VerifyDigestRequest.Builder b = VerifyDigestRequest.builder();
        c.accept(b);
        VerifyDigestRequest r = b.build();
        return verify(r);
    }

    default boolean verify(InputStream is, byte[] digest) {
        return verify(c -> c.payload(is).digest(digest));
    }

}

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

import java.io.InputStream;

/**
 * A request to verify a previously-computed cryptographic digest (available via {@link #getDigest()}) against the
 * digest to be computed for the specified {@link #getPayload() payload}.
 *
 * <p>Secure digest algorithms that use keys to perform
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication code</a> verification will use {@link VerifySecureDigestRequest} instead.</p>
 *
 * @see VerifySecureDigestRequest
 * @since 0.12.0
 */
public interface VerifyDigestRequest extends Request<InputStream>, DigestSupplier {

    /**
     * Named parameters (setters) used to configure a {@link VerifyDigestRequest VerifyDigestRequest} instance.
     *
     * @param <M> the instance type returned for method chaining.
     * @since 0.13.0
     */
    interface Params<M extends Params<M>> extends Request.Params<InputStream, M> {

        /**
         * The digest to verify against the one computed for the given {@link #getPayload() payload}.
         *
         * @param digest the digest to verify against the one computed for the given {@link #getPayload() payload}.
         * @return the instance for method chaining.
         */
        M digest(byte[] digest);
    }

    /**
     * A builder for creating new immutable {@link VerifyDigestRequest} instances.
     *
     * @since 0.13.0
     */
    interface Builder extends Params<Builder>, io.jsonwebtoken.lang.Builder<VerifyDigestRequest> {
    }
}

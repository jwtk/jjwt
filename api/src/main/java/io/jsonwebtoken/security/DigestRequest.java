/*
 * Copyright © 2026 jsonwebtoken.io
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
 * A request to an {@link DigestAlgorithm}, allowing either byte array or octet stream payloads.
 *
 * @see #getPayload()
 * @since JJWT_RELEASE_VERSION
 */
public interface DigestRequest extends Request<InputStream> {

    interface Params<P extends Params<P>> extends OctetStreamPayloadParams<P> {
    }

    /**
     * A builder for creating new immutable {@link DigestRequest} instances.
     *
     * @since JJWT_RELEASE_VERSION
     */
    interface Builder extends io.jsonwebtoken.lang.Builder<DigestRequest>, DigestRequest.Params<Builder> {
    }

    /**
     * Returns a new {@link DigestRequest.Builder} for creating immutable {@link DigestRequest}s.
     *
     * @return a new {@link DigestRequest.Builder} for creating immutable {@link DigestRequest}s.
     * @since JJWT_RELEASE_VERSION
     */
    static DigestRequest.Builder builder() {
        return Suppliers.DIGEST_REQUEST_BUILDER.get();
    }

}

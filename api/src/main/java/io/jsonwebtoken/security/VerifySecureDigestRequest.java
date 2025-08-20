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
import java.security.Key;

/**
 * A request to a {@link SecureDigestAlgorithm} to verify a previously-computed
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication code</a>.
 *
 * <p>The content to verify will be available via {@link #getPayload()}, the previously-computed signature or MAC will
 * be available via {@link #getDigest()}, and the verification key will be available via {@link #getKey()}.</p>
 *
 * @param <K> the type of {@link Key} used to verify a digital signature or message authentication code
 * @since 0.12.0
 */
public interface VerifySecureDigestRequest<K extends Key> extends SecureRequest<InputStream, K>, VerifyDigestRequest {

    /**
     * Named parameters (setters) used to configure a {@link VerifySecureDigestRequest VerifySecureDigestRequest}
     * instance.
     *
     * @param <K> type of key to use to verify the digest.
     * @param <M> the instance type returned for method chaining.
     * @since 0.13.0
     */
    interface Params<K extends Key, M extends Params<K, M>> extends SecureRequest.Params<InputStream, K, M>,
            VerifyDigestRequest.Params<M> {
    }

    /**
     * A builder for creating new immutable {@link VerifySecureDigestRequest} instances.
     *
     * @param <K> type of key used to verify the digest.
     * @since 0.13.0
     */
    interface Builder<K extends Key> extends Params<K, Builder<K>>, io.jsonwebtoken.lang.Builder<VerifySecureDigestRequest<K>> {
    }
}

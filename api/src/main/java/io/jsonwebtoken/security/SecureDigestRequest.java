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
import java.security.Key;

public interface SecureDigestRequest<K extends Key> extends DigestRequest, SecureRequest<InputStream, K> {

    /**
     * A builder for creating new immutable {@link SecureDigestRequest} instances.
     *
     * @since JJWT_RELEASE_VERSION
     */
    interface Builder<K extends Key> extends io.jsonwebtoken.lang.Builder<SecureDigestRequest<K>>, SecureDigestAlgorithm.Params<K, Builder<K>> {
    }

    /**
     * Returns a new {@link DigestRequest.Builder} for creating immutable {@link DigestRequest}s.
     *
     * @return a new {@link DigestRequest.Builder} for creating immutable {@link DigestRequest}s.
     * @since JJWT_RELEASE_VERSION
     */
    static <K extends Key> SecureDigestRequest.Builder<K> builder() {
        return Suppliers.secureDigestRequestBuilder();
    }
}

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
 * Request parameters that support an octet (byte array) {@link InputStream} payload.
 *
 * @param <T> The type of the params instance returned for method chaining.
 * @since JJWT_RELEASE_VERSION
 */
public interface OctetStreamPayloadParams<T extends OctetStreamPayloadParams<T>> extends Request.Params<InputStream, T> {

    /**
     * Wraps the request byte array in an {@link InputStream} and delegates to the {@link #payload(Object) payload} method.
     *
     * @param payload the byte array to wrap as an {@link InputStream} and use as the request payload.
     * @return the instance for method chaining.
     */
    default T payload(byte[] payload) {
        InputStream stream = Suppliers.BYTES_INPUT_STREAM_FACTORY.apply(payload);
        return payload(stream);
    }

}

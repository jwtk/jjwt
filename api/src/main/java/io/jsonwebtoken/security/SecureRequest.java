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

import java.security.Key;

/**
 * A request to a cryptographic algorithm requiring a {@link Key}.
 *
 * @param <T> the type of payload in the request
 * @param <K> they type of key used by the algorithm during the request
 * @since 0.12.0
 */
public interface SecureRequest<T, K extends Key> extends Request<T>, KeySupplier<K> {

    /**
     * Named parameters (setters) used to configure a {@link SecureRequest SecureRequest} instance.
     *
     * @param <T> the type of payload in the request.
     * @param <K> the type of key used by the algorithm during the request.
     * @param <M> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface Params<T, K extends Key, M extends Params<T, K, M>> extends Request.Params<T, M> {

        /**
         * Sets the key used by the algorithm during the request, must be compatible with the target algorithm.
         *
         * @param key the algorithm key to use during the request.
         * @return the instance for method chaining.
         */
        M key(K key);
    }

    /**
     * A builder for creating {@link SecureRequest}s used to compute a mac or signature via
     * {@link SecureDigestAlgorithm#digest(Request)}.
     *
     * @param <T> the type of payload in the request.
     * @param <K> the type of key used by the algorithm during the request.
     * @since JJWT_RELEASE_VERSION
     */
    interface Builder<T, K extends Key> extends Params<T, K, Builder<T, K>>, io.jsonwebtoken.lang.Builder<SecureRequest<T, K>> {
    }

    /**
     * Returns a new {@link SecureRequest.Builder} for creating {@link SecureRequest}s used to compute a mac or
     * signature via {@link SecureDigestAlgorithm#digest(Request)}.
     *
     * @param <T> the type of payload in the request.
     * @param <K> the type of key used by the algorithm to compute the digest.
     * @return a new {@link SecureRequest.Builder} for creating {@link SecureRequest}s used to compute a mac or
     * signature via {@link SecureDigestAlgorithm#digest(Request)}.
     * @since JJWT_RELEASE_VERSION
     */
    @SuppressWarnings("unchecked")
    static <T, K extends Key> SecureRequest.Builder<T, K> builder() {
        return (SecureRequest.Builder<T, K>) Suppliers.SECURE_REQUEST_BUILDER.get();
    }
}

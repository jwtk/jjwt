/*
 * Copyright © 2023 jsonwebtoken.io
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

import java.util.Collection;

/**
 * A key operation policy determines which {@link KeyOperation}s may be assigned to a JWK.
 *
 * @since JJWT_RELEASE_VERSION
 * @see JwkBuilder#operationPolicy(KeyOperationPolicy)
 */
public interface KeyOperationPolicy {

    /**
     * Returns all supported {@code KeyOperation}s that may be assigned to a JWK.
     *
     * @return all supported {@code KeyOperation}s that may be assigned to a JWK.
     */
    Collection<KeyOperation> getOperations();

    /**
     * Returns quietly if all of the specified key operations are allowed to be assigned to a JWK,
     * or throws an {@link IllegalArgumentException} otherwise.
     *
     * @param ops the operations to validate
     */
    @SuppressWarnings("GrazieInspection")
    void validate(Collection<KeyOperation> ops) throws IllegalArgumentException;
}

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

import io.jsonwebtoken.Identifiable;

/**
 * A {@code KeyOperation} identifies a behavior for which a key may be used. Key validation
 * algorithms may inspect a key's operations and reject the key if it is being used in a manner inconsistent
 * with its indicated operations.
 *
 * <p><b>KeyOperation Identifier</b></p>
 *
 * <p>This interface extends {@link Identifiable}; the value returned from {@link #getId()} is a
 * CaSe-SeNsItIvE value that uniquely identifies the operation among other KeyOperation instances.</p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">JWK key_ops (Key Operations) Parameter</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-8.3">JSON Web Key Operations Registry</a>
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyOperation extends Identifiable {

    /**
     * Returns a brief description of the key operation behavior.
     *
     * @return a brief description of the key operation behavior.
     */
    String getDescription();

    /**
     * Returns {@code true} if the specified {@code operation} is an acceptable use case for the key already assigned
     * this operation, {@code false} otherwise. As described in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">JWK key_ops (Key Operations) Parameter</a>
     * specification, Key validation algorithms will likely reject keys with inconsistent or unrelated operations
     * because of the security vulnerabilities that could occur otherwise.
     *
     * @param operation the key operation to check if it is related to (consistent or compatible with) this operation.
     * @return {@code true} if the specified {@code operation} is an acceptable use case for the key already assigned
     * this operation, {@code false} otherwise.
     */
    boolean isRelated(KeyOperation operation);
}

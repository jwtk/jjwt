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
package io.jsonwebtoken;

/**
 * A JwtVisitor supports the <a href="https://en.wikipedia.org/wiki/Visitor_pattern">Visitor design pattern</a> for
 * {@link Jwt} instances.  Visitor implementations define logic for a specific JWT subtype or payload subtype
 * avoiding type-checking if-then-else conditionals in favor of type-safe method dispatch when encountering a JWT.
 *
 * @param <T> the type of object to return after invoking the {@link Jwt#accept(JwtVisitor)} method.
 * @since 0.12.0
 */
public interface JwtVisitor<T> {

    /**
     * Handles an encountered Unsecured JWT that has not been cryptographically secured at all. Implementations can
     * check the {@link Jwt#getPayload()} to determine if it is a {@link Claims} instance or a {@code byte[]} array.
     *
     * <p>If the payload is a {@code byte[]} array, and the JWT creator has set the (optional)
     * {@link Header#getContentType()} value, the application may inspect that value to determine how to convert
     * the byte array to the final type as desired.</p>
     *
     * @param jwt the parsed Unsecured JWT.
     * @return any object to be used after inspecting the JWT, or {@code null} if no return value is necessary.
     */
    T visit(Jwt<?, ?> jwt);

    /**
     * Handles an encountered JSON Web Signature (aka 'JWS') message that has been cryptographically
     * verified/authenticated. Implementations can check the {@link Jwt#getPayload()} determine if it is a
     * {@link Claims} instance or a {@code byte[]} array.
     *
     * <p>If the payload is a {@code byte[]} array, and the JWS creator has set the (optional)
     * {@link Header#getContentType()} value, the application may inspect that value to determine how to convert
     * the byte array to the final type as desired.</p>
     *
     * @param jws the parsed verified/authenticated JWS.
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     */
    T visit(Jws<?> jws);

    /**
     * Handles an encountered JSON Web Encryption (aka 'JWE') message that has been authenticated and decrypted.
     * Implementations can check the (decrypted) {@link Jwt#getPayload()} to determine if it is a {@link Claims}
     * instance or a {@code byte[]} array.
     *
     * <p>If the payload is a {@code byte[]} array, and the JWE creator has set the (optional)
     * {@link Header#getContentType()} value, the application may inspect that value to determine how to convert
     * the byte array to the final type as desired.</p>
     *
     * @param jwe the parsed authenticated and decrypted JWE.
     * @return any object to be used after inspecting the JWE, or {@code null} if no return value is necessary.
     */
    T visit(Jwe<?> jwe);
}

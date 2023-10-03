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

import io.jsonwebtoken.lang.Assert;

/**
 * A {@code JwtVisitor} that guarantees only supported JWT instances are handled, rejecting
 * all other (unsupported) JWTs with {@link UnsupportedJwtException}s.  A JWT is considered supported
 * only if the type-specific handler method is overridden by a subclass.
 *
 * @param <T> the type of value returned from the subclass handler method implementation.
 * @since 0.12.0
 */
public class SupportedJwtVisitor<T> implements JwtVisitor<T> {

    /**
     * Default constructor, does not initialize any internal state.
     */
    public SupportedJwtVisitor() {
    }

    /**
     * Handles an encountered unsecured JWT by delegating to either {@link #onUnsecuredContent(Jwt)} or
     * {@link #onUnsecuredClaims(Jwt)} depending on the payload type.
     *
     * @param jwt the parsed unsecured JWT
     * @return the value returned by either {@link #onUnsecuredContent(Jwt)} or {@link #onUnsecuredClaims(Jwt)}
     * depending on the payload type.
     * @throws UnsupportedJwtException if the payload is neither a {@code byte[]} nor {@code Claims}, or either
     *                                 delegate method throws the same.
     */
    @SuppressWarnings("unchecked")
    @Override
    public T visit(Jwt<?, ?> jwt) {
        Assert.notNull(jwt, "JWT cannot be null.");
        Object payload = jwt.getPayload();
        if (payload instanceof byte[]) {
            return onUnsecuredContent((Jwt<Header, byte[]>) jwt);
        } else {
            // only other type we support:
            Assert.stateIsInstance(Claims.class, payload, "Unexpected payload data type: ");
            return onUnsecuredClaims((Jwt<Header, Claims>) jwt);
        }
    }

    /**
     * Handles an encountered unsecured content JWT - one that is not cryptographically signed nor
     * encrypted, and has a byte[] array payload. If the JWT creator has set the (optional)
     * {@link Header#getContentType()} value, the application may inspect that value to determine how to convert
     * the byte array to the final type as desired.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jwt the parsed unsecured content JWT
     * @return any object to be used after inspecting the JWT, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onUnsecuredContent(Jwt<Header, byte[]> jwt) throws UnsupportedJwtException {
        throw new UnsupportedJwtException("Unexpected unsecured content JWT.");
    }

    /**
     * Handles an encountered unsecured Claims JWT - one that is not cryptographically signed nor
     * encrypted, and has a {@link Claims} payload.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jwt the parsed unsecured content JWT
     * @return any object to be used after inspecting the JWT, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onUnsecuredClaims(Jwt<Header, Claims> jwt) {
        throw new UnsupportedJwtException("Unexpected unsecured Claims JWT.");
    }

    /**
     * Handles an encountered JSON Web Token (aka 'JWS') message that has been cryptographically verified/authenticated
     * by delegating to either {@link #onVerifiedContent(Jws)} or {@link #onVerifiedClaims(Jws)} depending on the payload
     * type.
     *
     * @param jws the parsed verified/authenticated JWS.
     * @return the value returned by either {@link #onVerifiedContent(Jws)} or {@link #onVerifiedClaims(Jws)}
     * depending on the payload type.
     * @throws UnsupportedJwtException if the payload is neither a {@code byte[]} nor {@code Claims}, or either
     *                                 delegate method throws the same.
     */
    @SuppressWarnings("unchecked")
    @Override
    public T visit(Jws<?> jws) {
        Assert.notNull(jws, "JWS cannot be null.");
        Object payload = jws.getPayload();
        if (payload instanceof byte[]) {
            return onVerifiedContent((Jws<byte[]>) jws);
        } else {
            Assert.stateIsInstance(Claims.class, payload, "Unexpected payload data type: ");
            return onVerifiedClaims((Jws<Claims>) jws);
        }
    }

    /**
     * Handles an encountered JWS message that has been cryptographically verified/authenticated and has
     * a byte[] array payload. If the JWT creator has set the (optional) {@link Header#getContentType()} value, the
     * application may inspect that value to determine how to convert the byte array to the final type as desired.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jws the parsed verified/authenticated JWS.
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onVerifiedContent(Jws<byte[]> jws) {
        throw new UnsupportedJwtException("Unexpected content JWS.");
    }

    /**
     * Handles an encountered JWS message that has been cryptographically verified/authenticated and has a
     * {@link Claims} payload.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jws the parsed signed (and verified) Claims JWS
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onVerifiedClaims(Jws<Claims> jws) {
        throw new UnsupportedJwtException("Unexpected Claims JWS.");
    }

    /**
     * Handles an encountered JSON Web Encryption (aka 'JWE') message that has been authenticated and decrypted by
     * delegating to either {@link #onDecryptedContent(Jwe)} or {@link #onDecryptedClaims(Jwe)} depending on the
     * payload type.
     *
     * @param jwe the parsed authenticated and decrypted JWE.
     * @return the value returned by either {@link #onDecryptedContent(Jwe)} or {@link #onDecryptedClaims(Jwe)}
     * depending on the payload type.
     * @throws UnsupportedJwtException if the payload is neither a {@code byte[]} nor {@code Claims}, or either
     *                                 delegate method throws the same.
     */
    @SuppressWarnings("unchecked")
    @Override
    public T visit(Jwe<?> jwe) {
        Assert.notNull(jwe, "JWE cannot be null.");
        Object payload = jwe.getPayload();
        if (payload instanceof byte[]) {
            return onDecryptedContent((Jwe<byte[]>) jwe);
        } else {
            Assert.stateIsInstance(Claims.class, payload, "Unexpected payload data type: ");
            return onDecryptedClaims((Jwe<Claims>) jwe);
        }
    }

    /**
     * Handles an encountered JWE message that has been authenticated and decrypted, and has byte[] array payload. If
     * the JWT creator has set the (optional) {@link Header#getContentType()} value, the application may inspect that
     * value to determine how to convert the byte array to the final type as desired.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jwe the parsed authenticated and decrypted content JWE.
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onDecryptedContent(Jwe<byte[]> jwe) {
        throw new UnsupportedJwtException("Unexpected content JWE.");
    }

    /**
     * Handles an encountered JWE message that has been authenticated and decrypted, and has a {@link Claims} payload.
     *
     * <p>The default implementation immediately throws an {@link UnsupportedJwtException}; it is expected that
     * subclasses will override this method if the application needs to support this type of JWT.</p>
     *
     * @param jwe the parsed authenticated and decrypted content JWE.
     * @return any object to be used after inspecting the JWE, or {@code null} if no return value is necessary.
     * @throws UnsupportedJwtException by default, expecting the subclass implementation to override as necessary.
     */
    public T onDecryptedClaims(Jwe<Claims> jwe) {
        throw new UnsupportedJwtException("Unexpected Claims JWE.");
    }
}

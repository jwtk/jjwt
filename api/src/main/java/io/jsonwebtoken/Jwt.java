/*
 * Copyright (C) 2014 jsonwebtoken.io
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
 * An expanded (not compact/serialized) JSON Web Token.
 *
 * @param <H> the type of the JWT header
 * @param <P> the type of the JWT payload, either a content byte array or a {@link Claims} instance.
 * @since 0.1
 */
public interface Jwt<H extends Header, P> {

    /**
     * Visitor implementation that ensures the visited JWT is an unsecured content JWT (one not cryptographically
     * signed or encrypted) and rejects all others with an {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onUnsecuredContent(Jwt)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jwt<Header, byte[]>> UNSECURED_CONTENT = new SupportedJwtVisitor<Jwt<Header, byte[]>>() {
        @Override
        public Jwt<Header, byte[]> onUnsecuredContent(Jwt<Header, byte[]> jwt) {
            return jwt;
        }
    };

    /**
     * Visitor implementation that ensures the visited JWT is an unsecured {@link Claims} JWT (one not
     * cryptographically signed or encrypted) and rejects all others with an {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onUnsecuredClaims(Jwt)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jwt<Header, Claims>> UNSECURED_CLAIMS = new SupportedJwtVisitor<Jwt<Header, Claims>>() {
        @Override
        public Jwt<Header, Claims> onUnsecuredClaims(Jwt<Header, Claims> jwt) {
            return jwt;
        }
    };

    /**
     * Returns the JWT {@link Header} or {@code null} if not present.
     *
     * @return the JWT {@link Header} or {@code null} if not present.
     */
    H getHeader();

    /**
     * Returns the JWT payload, either a {@code byte[]} or a {@code Claims} instance.  Use
     * {@link #getPayload()} instead, as this method will be removed prior to the 1.0 release.
     *
     * @return the JWT payload, either a {@code byte[]} or a {@code Claims} instance.
     * @deprecated since 0.12.0 because it has been renamed to {@link #getPayload()}.  'Payload' (not
     * body) is what the JWT specifications call this property, so it has been renamed to reflect the correct JWT
     * nomenclature/taxonomy.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    P getBody(); // TODO: remove for 1.0

    /**
     * Returns the JWT payload, either a {@code byte[]} or a {@code Claims} instance.  If the payload is a byte
     * array, and <em>if</em> the JWT creator set the (optional) {@link Header#getContentType() contentType} header
     * value, the application may inspect the {@code contentType} value to determine how to convert the byte array to
     * the final content type as desired.
     *
     * @return the JWT payload, either a {@code byte[]} or a {@code Claims} instance.
     * @since 0.12.0
     */
    P getPayload();

    /**
     * Invokes the specified {@code visitor}'s appropriate type-specific {@code visit} method based on this JWT's type.
     *
     * @param visitor the visitor to invoke.
     * @param <T>     the value type returned from the {@code visit} method.
     * @return the value returned from visitor's {@code visit} method implementation.
     */
    <T> T accept(JwtVisitor<T> visitor);
}

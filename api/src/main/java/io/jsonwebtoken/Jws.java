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
 * An expanded (not compact/serialized) Signed JSON Web Token.
 *
 * @param <P> the type of the JWS payload, either a byte[] or a {@link Claims} instance.
 * @since 0.1
 */
public interface Jws<P> extends ProtectedJwt<JwsHeader, P> {

    /**
     * Visitor implementation that ensures the visited JWT is a JSON Web Signature ('JWS') message with a
     * cryptographically authenticated/verified {@code byte[]} array payload, and rejects all others with an
     * {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onVerifiedContent(Jws)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jws<byte[]>> CONTENT = new SupportedJwtVisitor<Jws<byte[]>>() {
        @Override
        public Jws<byte[]> onVerifiedContent(Jws<byte[]> jws) {
            return jws;
        }
    };

    /**
     * Visitor implementation that ensures the visited JWT is a JSON Web Signature ('JWS') message with a
     * cryptographically authenticated/verified {@link Claims} payload, and rejects all others with an
     * {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onVerifiedClaims(Jws)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jws<Claims>> CLAIMS = new SupportedJwtVisitor<Jws<Claims>>() {
        @Override
        public Jws<Claims> onVerifiedClaims(Jws<Claims> jws) {
            return jws;
        }
    };

    /**
     * Returns the verified JWS signature as a Base64Url string.
     *
     * @return the verified JWS signature as a Base64Url string.
     * @deprecated since 0.12.0 in favor of {@link #getDigest() getDigest()}.
     */
    @Deprecated
    String getSignature(); //TODO for 1.0: return a byte[]
}

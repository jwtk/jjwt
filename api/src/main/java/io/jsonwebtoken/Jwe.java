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
package io.jsonwebtoken;

/**
 * An encrypted JWT, called a &quot;JWE&quot;, per the
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html">JWE (RFC 7516) Specification</a>.
 *
 * @param <B> payload type, either {@link Claims} or {@code byte[]} content.
 * @since 0.12.0
 */
public interface Jwe<B> extends ProtectedJwt<JweHeader, B> {

    /**
     * Visitor implementation that ensures the visited JWT is a JSON Web Encryption ('JWE') message with an
     * authenticated and decrypted {@code byte[]} array payload, and rejects all others with an
     * {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onDecryptedContent(Jwe)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jwe<byte[]>> CONTENT = new SupportedJwtVisitor<Jwe<byte[]>>() {
        @Override
        public Jwe<byte[]> onDecryptedContent(Jwe<byte[]> jwe) {
            return jwe;
        }
    };

    /**
     * Visitor implementation that ensures the visited JWT is a JSON Web Encryption ('JWE') message with an
     * authenticated and decrypted {@link Claims} payload, and rejects all others with an
     * {@link UnsupportedJwtException}.
     *
     * @see SupportedJwtVisitor#onDecryptedClaims(Jwe)
     * @since 0.12.0
     */
    @SuppressWarnings("UnnecessaryModifier")
    public static final JwtVisitor<Jwe<Claims>> CLAIMS = new SupportedJwtVisitor<Jwe<Claims>>() {
        @Override
        public Jwe<Claims> onDecryptedClaims(Jwe<Claims> jwe) {
            return jwe;
        }
    };

    /**
     * Returns the Initialization Vector used during JWE encryption and decryption.
     *
     * @return the Initialization Vector used during JWE encryption and decryption.
     */
    byte[] getInitializationVector();
}

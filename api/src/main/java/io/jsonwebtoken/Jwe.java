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

import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.AeadAlgorithm;

/**
 * An encrypted JWT, called a &quot;JWE&quot;, per the
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html">JWE (RFC 7516) Specification</a>.
 *
 * @param <B> payload type, either {@link Claims} or {@code byte[]} content.
 * @since 0.12.0
 */
public interface Jwe<B> extends ProtectedJwt<JweHeader, B> {

    /**
     * Constants for all standard JWA
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic Algorithms for Content
     * Encryption</a> defined in the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON
     * Web Signature and Encryption Algorithms Registry</a>. Each standard algorithm is available as a
     * ({@code public static final}) constant for direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwe.alg.A256GCM</b>) // or A128GCM, A192GCM, etc...
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #registry()} method.</p>
     *
     * @see #registry()
     * @since JJWT_RELEASE_VERSION
     */
    final class alg {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardEncryptionAlgorithms";
        private static final Registry<String, AeadAlgorithm> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns all standard JWA <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic
         * Algorithms for Content Encryption</a> defined in the
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
         * Algorithms Registry</a>.
         *
         * @return all standard JWA content encryption algorithms.
         */
        public static Registry<String, AeadAlgorithm> registry() {
            return REGISTRY;
        }

        // prevent instantiation
        private alg() {
        }

        /**
         * {@code AES_128_CBC_HMAC_SHA_256} authenticated encryption algorithm as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
         * requires a 256-bit (32 byte) key.
         */
        public static final AeadAlgorithm A128CBC_HS256 = registry().forKey("A128CBC-HS256");

        /**
         * {@code AES_192_CBC_HMAC_SHA_384} authenticated encryption algorithm, as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
         * requires a 384-bit (48 byte) key.
         */
        public static final AeadAlgorithm A192CBC_HS384 = registry().forKey("A192CBC-HS384");

        /**
         * {@code AES_256_CBC_HMAC_SHA_512} authenticated encryption algorithm, as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
         * requires a 512-bit (64 byte) key.
         */
        public static final AeadAlgorithm A256CBC_HS512 = registry().forKey("A256CBC-HS512");

        /**
         * &quot;AES GCM using 128-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This
         * algorithm requires a 128-bit (16 byte) key.
         */
        public static final AeadAlgorithm A128GCM = registry().forKey("A128GCM");

        /**
         * &quot;AES GCM using 192-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This
         * algorithm requires a 192-bit (24 byte) key.
         */
        public static final AeadAlgorithm A192GCM = registry().forKey("A192GCM");

        /**
         * &quot;AES GCM using 256-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This
         * algorithm requires a 256-bit (32 byte) key.
         */
        public static final AeadAlgorithm A256GCM = registry().forKey("A256GCM");
    }

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

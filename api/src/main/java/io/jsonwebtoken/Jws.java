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

import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.KeyPairBuilderSupplier;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import java.security.Key;

/**
 * An expanded (not compact/serialized) Signed JSON Web Token.
 *
 * @param <P> the type of the JWS payload, either a byte[] or a {@link Claims} instance.
 * @since 0.1
 */
public interface Jws<P> extends ProtectedJwt<JwsHeader, P> {

    /**
     * Constants for all JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">
     * Cryptographic Algorithms for Digital Signatures and MACs</a> defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption Algorithms
     * Registry</a>. Each standard algorithm is available as a ({@code public static final}) constant for
     * direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .signWith(aKey, <b>Jws.alg.HS512</b>) // or RS512, PS256, EdDSA, etc...
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #registry()} method.</p>
     *
     * @see #registry()
     * @since JJWT_RELEASE_VERSION
     */
    final class alg {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithms";
        private static final Registry<String, SecureDigestAlgorithm<?, ?>> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        //prevent instantiation
        private alg() {
        }

        /**
         * Returns all standard JWA <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic
         * Algorithms for Digital Signatures and MACs</a> defined in the
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
         * Algorithms Registry</a>.
         *
         * @return all standard JWA digital signature and MAC algorithms.
         */
        public static Registry<String, SecureDigestAlgorithm<?, ?>> registry() {
            return REGISTRY;
        }

        /**
         * The &quot;none&quot; signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section 3.6</a>.  This algorithm
         * is used only when creating unsecured (not integrity protected) JWSs and is not usable in any other scenario.
         * Any attempt to call its methods will result in an exception being thrown.
         */
        public static final SecureDigestAlgorithm<Key, Key> NONE = Jwts.get(REGISTRY, "none");

        /**
         * {@code HMAC using SHA-256} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 256-bit (32 byte) key.
         */
        public static final MacAlgorithm HS256 = Jwts.get(REGISTRY, "HS256");

        /**
         * {@code HMAC using SHA-384} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 384-bit (48 byte) key.
         */
        public static final MacAlgorithm HS384 = Jwts.get(REGISTRY, "HS384");

        /**
         * {@code HMAC using SHA-512} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 512-bit (64 byte) key.
         */
        public static final MacAlgorithm HS512 = Jwts.get(REGISTRY, "HS512");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm RS256 = Jwts.get(REGISTRY, "RS256");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm RS384 = Jwts.get(REGISTRY, "RS384");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm RS512 = Jwts.get(REGISTRY, "RS512");

        /**
         * {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm PS256 = Jwts.get(REGISTRY, "PS256");

        /**
         * {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm PS384 = Jwts.get(REGISTRY, "PS384");

        /**
         * {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm PS512 = Jwts.get(REGISTRY, "PS512");

        /**
         * {@code ECDSA using P-256 and SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 256-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm ES256 = Jwts.get(REGISTRY, "ES256");

        /**
         * {@code ECDSA using P-384 and SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 384-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm ES384 = Jwts.get(REGISTRY, "ES384");

        /**
         * {@code ECDSA using P-521 and SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 521-bit key.
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm ES512 = Jwts.get(REGISTRY, "ES512");

        /**
         * {@code EdDSA} signature algorithm defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a> that requires
         * either {@code Ed25519} or {@code Ed448} Edwards Elliptic Curve<sup><b>1</b></sup> keys.
         *
         * <p><b>KeyPair Generation</b></p>
         *
         * <p>This instance's {@link KeyPairBuilderSupplier#keyPair() keyPair()} builder creates {@code Ed448} keys,
         * and is essentially an alias for
         * <code>{@link io.jsonwebtoken.security.Jwks.CRV Jwks.CRV}.{@link io.jsonwebtoken.security.Jwks.CRV#Ed448 Ed448}.{@link KeyPairBuilderSupplier#keyPair() keyPair()}</code>.</p>
         *
         * <p>If you would like to generate an {@code Ed25519} {@code KeyPair} for use with the {@code EdDSA} algorithm,
         * you may use the
         * <code>{@link io.jsonwebtoken.security.Jwks.CRV Jwks.CRV}.{@link io.jsonwebtoken.security.Jwks.CRV#Ed25519 Ed25519}.{@link KeyPairBuilderSupplier#keyPair() keyPair()}</code>
         * builder instead.</p>
         *
         * <p><b><sup>1</sup>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final io.jsonwebtoken.security.SignatureAlgorithm EdDSA = Jwts.get(REGISTRY, "EdDSA");
    }

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

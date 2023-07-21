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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.DelegatingRegistry;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.StandardKeyAlgorithms;

import java.security.Key;
import java.util.Map;

/**
 * Factory class useful for creating instances of JWT interfaces.  Using this factory class can be a good
 * alternative to tightly coupling your code to implementation classes.
 *
 * <p><b>Standard Algorithm References</b></p>
 * <p>Standard JSON Web Token algorithms used during JWS or JWE building or parsing are available organized by
 * algorithm type. Each organized collection of algorithms is available via a constant to allow
 * for easy code-completion in IDEs, showing available algorithm instances.  For example, when typing:</p>
 * <blockquote><pre>
 * Jwts.// press code-completion hotkeys to suggest available algorithm registry fields
 * Jwts.{@link SIG SIG}.// press hotkeys to suggest individual Digital Signature or MAC algorithms or utility methods
 * Jwts.{@link ENC ENC}.// press hotkeys to suggest individual encryption algorithms or utility methods
 * Jwts.{@link #KEY}.// press hotkeys to suggest individual key algorithms or utility methods</pre></blockquote>
 *
 * @since 0.1
 */
public final class Jwts {

    @SuppressWarnings("rawtypes")
    private static final Class[] MAP_ARG = new Class[]{Map.class};

    private static class ImplRegistry<V> extends DelegatingRegistry<String, V> {

        protected ImplRegistry(String implClassName) {
            super(Classes.<Registry<String, V>>newInstance(implClassName));
        }

        // do not change this visibility.  Raw type method signature not be publicly exposed
        @SuppressWarnings("unchecked")
        <T> T doForKey(String id) {
            Assert.hasText(id, "id cannot be null or empty.");
            return (T) forKey(id);
        }
    }

    /**
     * Convenience constants for all standard JWA
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic Algorithms for Content Encryption</a>
     * defined in the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">
     * JSON Web Signature and Encryption Algorithms Registry</a>. Each standard algorithm
     * is available as a ({@code public static final}) constant for direct type-safe reference in application code.
     * For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.ENC.A256GCM</b>) // or A128GCM, A192GCM, etc...
     *    .build();</pre></blockquote>
     * </p>
     * <p>Additionally, all standard Content Encryption algorithms are available via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class ENC {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardEncryptionAlgorithmsBridge";
        private static final Registry<String, AeadAlgorithm> REGISTRY = new ImplRegistry<>(IMPL_CLASSNAME);

        /**
         * Returns all standard JWA <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic
         * Algorithms for Content Encryption</a> defined in the
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
         * Algorithms Registry</a>.
         *
         * @return all standard JWA content encryption algorithms.
         */
        public static Registry<String, AeadAlgorithm> get() {
            return REGISTRY;
        }

        private ENC() {
        } // prevent instantiation

        /**
         * {@code AES_128_CBC_HMAC_SHA_256} authenticated encryption algorithm as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
         * requires a 256-bit (32 byte) key.
         */
        public static final AeadAlgorithm A128CBC_HS256 = get().forKey("A128CBC-HS256");

        /**
         * {@code AES_192_CBC_HMAC_SHA_384} authenticated encryption algorithm, as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
         * requires a 384-bit (48 byte) key.
         */
        public static final AeadAlgorithm A192CBC_HS384 = get().forKey("A192CBC-HS384");

        /**
         * {@code AES_256_CBC_HMAC_SHA_512} authenticated encryption algorithm, as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
         * requires a 512-bit (64 byte) key.
         */
        public static final AeadAlgorithm A256CBC_HS512 = get().forKey("A256CBC-HS512");

        /**
         * &quot;AES GCM using 128-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
         * algorithm requires a 128-bit (16 byte) key.
         *
         * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final AeadAlgorithm A128GCM = get().forKey("A128GCM");

        /**
         * &quot;AES GCM using 192-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
         * algorithm requires a 192-bit (24 byte) key.
         *
         * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final AeadAlgorithm A192GCM = get().forKey("A192GCM");

        /**
         * &quot;AES GCM using 256-bit key&quot; as defined by
         * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
         * algorithm requires a 256-bit (32 byte) key.
         *
         * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final AeadAlgorithm A256GCM = get().forKey("A256GCM");
    }

    /**
     * All JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic
     * Algorithms for Digital Signatures and MACs</a> defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption Algorithms
     * Registry</a>. In addition to its
     * {@link Registry#forKey(Object) forKey} and {@link Registry#get(Object) get} lookup methods, each standard algorithm
     * is also available as a ({@code public final}) constant for direct type-safe reference in application code.
     * For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .signWith(aKey, <b>Jwts.SIG.HS512</b>) // or RS512, PS256, EdDSA, etc...
     *    .build();</pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final class SIG {
        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithmsBridge";
        private static final ImplRegistry<SecureDigestAlgorithm<?, ?>> REGISTRY = new ImplRegistry<>(IMPL_CLASSNAME);

        /**
         * Returns all standard JWA <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic
         * Algorithms for Digital Signatures and MACs</a> defined in the
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
         * Algorithms Registry</a>.
         *
         * @return all standard JWA content encryption algorithms.
         */
        public static Registry<String, SecureDigestAlgorithm<?, ?>> get() {
            return REGISTRY;
        }

        /**
         * The &quot;none&quot; signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section 3.6</a>.  This algorithm
         * is used only when creating unsecured (not integrity protected) JWSs and is not usable in any other scenario.
         * Any attempt to call its methods will result in an exception being thrown.
         */
        public static final SecureDigestAlgorithm<Key, Key> NONE = REGISTRY.doForKey("none");

        /**
         * {@code HMAC using SHA-256} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 256-bit (32 byte) key.
         */
        public static final MacAlgorithm HS256 = REGISTRY.doForKey("HS256");

        /**
         * {@code HMAC using SHA-384} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 384-bit (48 byte) key.
         */
        public static final MacAlgorithm HS384 = REGISTRY.doForKey("HS384");

        /**
         * {@code HMAC using SHA-512} message authentication algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
         * requires a 512-bit (64 byte) key.
         */
        public static final MacAlgorithm HS512 = REGISTRY.doForKey("HS512");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key.
         */
        public static final SignatureAlgorithm RS256 = REGISTRY.doForKey("RS256");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         */
        public static final SignatureAlgorithm RS384 = REGISTRY.doForKey("RS384");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         */
        public static final SignatureAlgorithm RS512 = REGISTRY.doForKey("RS512");

        /**
         * {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS256 = REGISTRY.doForKey("PS256");

        /**
         * {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS384 = REGISTRY.doForKey("PS384");

        /**
         * {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS512 = REGISTRY.doForKey("PS512");

        /**
         * {@code ECDSA using P-256 and SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 256-bit key.
         */
        public static final SignatureAlgorithm ES256 = REGISTRY.doForKey("ES256");

        /**
         * {@code ECDSA using P-384 and SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 384-bit key.
         */
        public static final SignatureAlgorithm ES384 = REGISTRY.doForKey("ES384");

        /**
         * {@code ECDSA using P-521 and SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 521-bit key.
         */
        public static final SignatureAlgorithm ES512 = REGISTRY.doForKey("ES512");

        /**
         * {@code EdDSA} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
         * requires either {@code Ed25519} or {@code Ed448} Edwards Curve keys.
         * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final SignatureAlgorithm EdDSA = REGISTRY.doForKey("EdDSA");

        /**
         * {@code EdDSA} signature algorithm using Curve {@code Ed25519} as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
         * requires {@code Ed25519} Edwards Curve keys to create signatures.  <b>This is a convenience alias for
         * {@link #EdDSA}</b> that defaults key generation to {@code Ed25519} keys.
         * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final SignatureAlgorithm Ed25519 = REGISTRY.doForKey("Ed25519");

        /**
         * {@code EdDSA} signature algorithm using Curve {@code Ed448} as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
         * requires {@code Ed448} Edwards Curve keys to create signatures. <b>This is a convenience alias for
         * {@link #EdDSA}</b> that defaults key generation to {@code Ed448} keys.
         * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final SignatureAlgorithm Ed448 = REGISTRY.doForKey("Ed448");

    }

    /**
     * All JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">Cryptographic
     * Algorithms for Key Management</a>. In addition to its
     * convenience {@link Registry#forKey(Object) forKey} and {@link Registry#get(Object) get} lookup methods, each
     * standard algorithm is also available as a ({@code public final}) constant for direct type-safe reference in
     * application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.KEY.ECDH_ES_A256KW</b>, Jwts.ENC.A256GCM)
     *    .build();</pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final StandardKeyAlgorithms KEY = StandardKeyAlgorithms.get();

    /**
     * Private constructor, prevent instantiation.
     */
    private Jwts() {
    }

    /**
     * Returns a new {@link JwtHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     *
     * @return a new {@link JwtHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     * @since JJWT_RELEASE_VERSION
     */
    public static JwtHeaderBuilder header() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtHeaderBuilder");
    }

    /**
     * Returns a new {@link Claims} builder instance to be used to populate JWT claims, which in aggregate will be
     * the JWT payload.
     *
     * @return a new {@link Claims} builder instance to be used to populate JWT claims, which in aggregate will be
     * the JWT payload.
     */
    public static ClaimsBuilder claims() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultClaimsBuilder");
    }

    /**
     * <p><b>Deprecated since JJWT_RELEASE_VERSION in favor of
     * {@code Jwts.}{@link #claims()}{@code .putAll(map).build()}</b>.
     * This method will be removed before 1.0.</p>
     *
     * <p>Returns a new {@link Claims} instance populated with the specified name/value pairs.</p>
     *
     * @param claims the name/value pairs to populate the new Claims instance.
     * @return a new {@link Claims} instance populated with the specified name/value pairs.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@code Jwts.}{@link #claims()}{@code .putAll(map).build()}.
     * This method will be removed before 1.0.
     */
    @Deprecated
    public static Claims claims(Map<String, Object> claims) {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultClaims", MAP_ARG, claims);
    }

    /**
     * Returns a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     *
     * @return a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     * @deprecated use {@link Jwts#parserBuilder()} instead. See {@link JwtParserBuilder} for usage details.
     * <p>Migration to new method structure is minimal, for example:
     * <p>Old code:
     * <pre>{@code
     *     Jwts.parser()
     *         .requireAudience("string")
     *         .parse(jwtString)
     * }</pre>
     * <p>New code:
     * <pre>{@code
     *     Jwts.parserBuilder()
     *         .requireAudience("string")
     *         .build()
     *         .parse(jwtString)
     * }</pre>
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    public static JwtParser parser() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParser");
    }

    /**
     * Returns a new {@link JwtParserBuilder} instance that can be configured to create an immutable/thread-safe {@link JwtParser}.
     *
     * @return a new {@link JwtParser} instance that can be configured create an immutable/thread-safe {@link JwtParser}.
     */
    public static JwtParserBuilder parserBuilder() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParserBuilder");
    }

    /**
     * Returns a new {@link JwtBuilder} instance that can be configured and then used to create JWT compact serialized
     * strings.
     *
     * @return a new {@link JwtBuilder} instance that can be configured and then used to create JWT compact serialized
     * strings.
     */
    public static JwtBuilder builder() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtBuilder");
    }
}

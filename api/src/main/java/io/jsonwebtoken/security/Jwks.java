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
package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;

/**
 * Utility methods for creating
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JWKs (JSON Web Keys)</a> with a type-safe builder.
 *
 * <p><b>Standard JWK Thumbprint Algorithm References</b></p>
 * <p>Standard <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
 * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
 * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>
 * are available via the {@link Jwks.HASH} registry constants to allow for easy code-completion in IDEs. For example, when
 * typing:</p>
 * <blockquote><pre>
 * Jwks.{@link Jwks.HASH HASH}.// press hotkeys to suggest individual hash algorithms or utility methods</pre></blockquote>
 *
 * @see #builder()
 * @since JJWT_RELEASE_VERSION
 */
public final class Jwks {

    private Jwks() {
    } //prevent instantiation

    private static final String BUILDER_CLASSNAME = "io.jsonwebtoken.impl.security.DefaultDynamicJwkBuilder";

    private static final String PARSERBUILDER_CLASSNAME = "io.jsonwebtoken.impl.security.DefaultJwkParserBuilder";

    /**
     * Various (<em>but not all</em>)
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
     * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
     * Each algorithm is made available as a ({@code public static final}) constant for direct type-safe
     * reference in application code. For example:
     * <blockquote><pre>
     * Jwks.{@link Jwks#builder}()
     *     // ... etc ...
     *     .{@link JwkBuilder#idFromThumbprint(HashAlgorithm) idFromThumbprint}(Jwts.HASH.{@link Jwks.HASH#SHA256 SHA256}) // &lt;---
     *     .build()</pre></blockquote>
     * <p>or</p>
     * <blockquote><pre>
     * HashAlgorithm hashAlg = Jwks.HASH.{@link Jwks.HASH#SHA256 SHA256};
     * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
     * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
     * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
     * </pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class HASH {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardHashAlgorithms";
        private static final Registry<String, HashAlgorithm> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns a registry of various (<em>but not all</em>)
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
         * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
         * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
         *
         * @return a registry of various (<em>but not all</em>)
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
         * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
         * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
         */
        public static Registry<String, HashAlgorithm> get() {
            return REGISTRY;
        }

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-256} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA256 = get().forKey("sha-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-384} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA384 = get().forKey("sha-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-512} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA512 = get().forKey("sha-512");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-256} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_256 = get().forKey("sha3-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-384} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_384 = get().forKey("sha3-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-512} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_512 = get().forKey("sha3-512");

        //prevent instantiation
        private HASH() {
        }
    }

    /**
     * Return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     *
     * @return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     */
    public static DynamicJwkBuilder<?, ?> builder() {
        return Classes.newInstance(BUILDER_CLASSNAME);
    }

    /**
     * Return a new thread-safe {@link JwkParserBuilder} to parse JSON strings into {@link Jwk} instances.
     *
     * @return a new thread-safe {@link JwkParserBuilder} to parse JSON strings into {@link Jwk} instances.
     */
    public static JwkParserBuilder parser() {
        return Classes.newInstance(PARSERBUILDER_CLASSNAME);
    }

}

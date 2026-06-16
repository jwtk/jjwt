/*
 * Copyright © 2022 jsonwebtoken.io
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

import java.net.URI;

/**
 * A canonical cryptographic digest of a JWK as defined by the
 * <a href="https://www.rfc-editor.org/rfc/rfc7638">JSON Web Key (JWK) Thumbprint</a> specification.
 *
 * @since 0.12.0
 */
public interface JwkThumbprint {

    /**
     * Various (<em>but not all</em>)
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
     * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.
     * Each algorithm is made available as a ({@code public static final}) constant for direct type-safe
     * reference in application code. For example:
     * <blockquote><pre>
     * Jwks.{@link Jwks#builder builder}()
     *     // ... etc ...
     *     .{@link JwkBuilder#idFromThumbprint(HashAlgorithm) idFromThumbprint}(JwkThumbprint.alg.{@link JwkThumbprint.alg#SHA256 SHA256}) // &lt;---
     *     .build()</pre></blockquote>
     * <p>or</p>
     * <blockquote><pre>
     * HashAlgorithm hashAlg = JwkThumbprint.alg.{@link JwkThumbprint.alg#SHA256 SHA256};
     * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
     * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
     * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
     * </pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #registry()} method.</p>
     *
     * @see #registry()
     * @since JJWT_RELEASE_VERSION
     */
    final class alg {

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
        public static Registry<String, HashAlgorithm> registry() {
            return REGISTRY;
        }

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-256} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA256 = registry().forKey("sha-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-384} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA384 = registry().forKey("sha-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA-512} {@code MessageDigest} algorithm.
         */
        public static final HashAlgorithm SHA512 = registry().forKey("sha-512");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-256}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-256} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_256 = registry().forKey("sha3-256");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-384}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-384} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_384 = registry().forKey("sha3-384");

        /**
         * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
         * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
         * value of {@code sha3-512}. It is a {@code HashAlgorithm} alias for the native
         * Java JCA {@code SHA3-512} {@code MessageDigest} algorithm.
         * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath.</b></p>
         */
        public static final HashAlgorithm SHA3_512 = registry().forKey("sha3-512");

        //prevent instantiation
        private alg() {
        }
    }

    /**
     * Returns the {@link HashAlgorithm} used to compute the thumbprint.
     *
     * @return the {@link HashAlgorithm} used to compute the thumbprint.
     */
    HashAlgorithm getHashAlgorithm();

    /**
     * Returns the actual thumbprint (aka digest) byte array value.
     *
     * @return the actual thumbprint (aka digest) byte array value.
     */
    byte[] toByteArray();

    /**
     * Returns the canonical URI representation of this thumbprint as defined by the
     * <a href="https://www.rfc-editor.org/rfc/rfc9278.html">JWK Thumbprint URI</a> specification.
     *
     * @return a canonical JWK Thumbprint URI
     */
    URI toURI();

    /**
     * Returns the {@link #toByteArray()} value as a Base64URL-encoded string.
     */
    String toString();
}

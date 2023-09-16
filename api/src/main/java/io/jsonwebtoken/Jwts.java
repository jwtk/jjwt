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

import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Builder;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyPairBuilderSupplier;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.X509Builder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
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
 * Jwts.{@link KEY KEY}.// press hotkeys to suggest individual key algorithms or utility methods</pre></blockquote>
 *
 * @since 0.1
 */
public final class Jwts {


    // do not change this visibility.  Raw type method signature not be publicly exposed:
    @SuppressWarnings("unchecked")
    private static <T> T get(Registry<String, ?> registry, String id) {
        return (T) registry.forKey(id);
    }

    /**
     * Constants for all standard JWA
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic Algorithms for Content
     * Encryption</a> defined in the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON
     * Web Signature and Encryption Algorithms Registry</a>. Each standard algorithm is available as a
     * ({@code public static final}) constant for direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.ENC.A256GCM</b>) // or A128GCM, A192GCM, etc...
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class ENC {

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
        public static Registry<String, AeadAlgorithm> get() {
            return REGISTRY;
        }

        // prevent instantiation
        private ENC() {
        }

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
     * Constants for all JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">
     * Cryptographic Algorithms for Digital Signatures and MACs</a> defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption Algorithms
     * Registry</a>. Each standard algorithm is available as a ({@code public static final}) constant for
     * direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .signWith(aKey, <b>Jwts.SIG.HS512</b>) // or RS512, PS256, EdDSA, etc...
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class SIG {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithms";
        private static final Registry<String, SecureDigestAlgorithm<?, ?>> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        //prevent instantiation
        private SIG() {
        }

        /**
         * Returns all standard JWA <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic
         * Algorithms for Digital Signatures and MACs</a> defined in the
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption
         * Algorithms Registry</a>.
         *
         * @return all standard JWA digital signature and MAC algorithms.
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
        public static final SignatureAlgorithm RS256 = Jwts.get(REGISTRY, "RS256");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         */
        public static final SignatureAlgorithm RS384 = Jwts.get(REGISTRY, "RS384");

        /**
         * {@code RSASSA-PKCS1-v1_5 using SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
         * requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         */
        public static final SignatureAlgorithm RS512 = Jwts.get(REGISTRY, "RS512");

        /**
         * {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS256 = Jwts.get(REGISTRY, "PS256");

        /**
         * {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS384 = Jwts.get(REGISTRY, "PS384");

        /**
         * {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
         * This algorithm requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
         *
         * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
         * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
         * classpath.</p>
         */
        public static final SignatureAlgorithm PS512 = Jwts.get(REGISTRY, "PS512");

        /**
         * {@code ECDSA using P-256 and SHA-256} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 256-bit key.
         */
        public static final SignatureAlgorithm ES256 = Jwts.get(REGISTRY, "ES256");

        /**
         * {@code ECDSA using P-384 and SHA-384} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 384-bit key.
         */
        public static final SignatureAlgorithm ES384 = Jwts.get(REGISTRY, "ES384");

        /**
         * {@code ECDSA using P-521 and SHA-512} signature algorithm as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
         * requires a 521-bit key.
         */
        public static final SignatureAlgorithm ES512 = Jwts.get(REGISTRY, "ES512");

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
        public static final SignatureAlgorithm EdDSA = Jwts.get(REGISTRY, "EdDSA");
    }

    /**
     * Constants for all standard JWA (RFC 7518) <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">
     * Cryptographic Algorithms for Key Management</a>. Each standard algorithm is available as a
     * ({@code public static final}) constant for direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.KEY.ECDH_ES_A256KW</b>, Jwts.ENC.A256GCM)
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class KEY {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardKeyAlgorithms";
        private static final Registry<String, KeyAlgorithm<?, ?>> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns all standard JWA standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">Cryptographic
         * Algorithms for Key Management</a>..
         *
         * @return all standard JWA Key Management algorithms.
         */
        public static Registry<String, KeyAlgorithm<?, ?>> get() {
            return REGISTRY;
        }

        /**
         * Key algorithm reflecting direct use of a shared symmetric key as the JWE AEAD encryption key, as defined
         * by <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.5">RFC 7518 (JWA), Section 4.5</a>.  This
         * algorithm does not produce encrypted key ciphertext.
         */
        public static final KeyAlgorithm<SecretKey, SecretKey> DIRECT = Jwts.get(REGISTRY, "dir");

        /**
         * AES Key Wrap algorithm with default initial value using a 128-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 128-bit shared symmetric key using the
         *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the 128-bit shared symmetric key,
         *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A128KW = Jwts.get(REGISTRY, "A128KW");

        /**
         * AES Key Wrap algorithm with default initial value using a 192-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 192-bit shared symmetric key using the
         *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the 192-bit shared symmetric key,
         *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A192KW = Jwts.get(REGISTRY, "A192KW");

        /**
         * AES Key Wrap algorithm with default initial value using a 256-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 256-bit shared symmetric key using the
         *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the 256-bit shared symmetric key,
         *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A256KW = Jwts.get(REGISTRY, "A256KW");

        /**
         * Key wrap algorithm with AES GCM using a 128-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 128-bit shared symmetric key using the
         *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
         *     and GCM authentication tag.</li>
         *     <li>Sets the generated initialization vector as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Sets the resulting GCM authentication tag as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Obtains the required initialization vector from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Obtains the required GCM authentication tag from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Decrypts the encrypted key ciphertext with the 128-bit shared symmetric key, the initialization vector
         *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key
         *     plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A128GCMKW = Jwts.get(REGISTRY, "A128GCMKW");

        /**
         * Key wrap algorithm with AES GCM using a 192-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 192-bit shared symmetric key using the
         *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
         *     and GCM authentication tag.</li>
         *     <li>Sets the generated initialization vector as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Sets the resulting GCM authentication tag as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Obtains the required initialization vector from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Obtains the required GCM authentication tag from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Decrypts the encrypted key ciphertext with the 192-bit shared symmetric key, the initialization vector
         *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key \
         *     plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A192GCMKW = Jwts.get(REGISTRY, "A192GCMKW");

        /**
         * Key wrap algorithm with AES GCM using a 256-bit key, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with a 256-bit shared symmetric key using the
         *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
         *     and GCM authentication tag.</li>
         *     <li>Sets the generated initialization vector as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Sets the resulting GCM authentication tag as the required
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Obtains the required initialization vector from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
         *     (Initialization Vector) Header Parameter</a></li>
         *     <li>Obtains the required GCM authentication tag from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
         *     (Authentication Tag) Header Parameter</a></li>
         *     <li>Decrypts the encrypted key ciphertext with the 256-bit shared symmetric key, the initialization vector
         *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key \
         *     plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final SecretKeyAlgorithm A256GCMKW = Jwts.get(REGISTRY, "A256GCMKW");

        /**
         * Key encryption algorithm using <code>PBES2 with HMAC SHA-256 and &quot;A128KW&quot; wrapping</code>
         * as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8">RFC 7518 (JWA), Section 4.8</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Determines the number of PBDKF2 iterations via the JWE header's
         *     {@link JweHeader#getPbes2Count() pbes2Count} value.  If that value is not set, a suitable number of
         *     iterations will be chosen based on
         *     <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">OWASP
         *     PBKDF2 recommendations</a> and then that value is set as the JWE header {@code pbes2Count} value.</li>
         *     <li>Generates a new secure-random salt input and sets it as the JWE header
         *     {@link JweHeader#getPbes2Salt() pbes2Salt} value.</li>
         *     <li>Derives a 128-bit Key Encryption Key with the PBES2-HS256 password-based key derivation algorithm,
         *     using the provided password, iteration count, and input salt as arguments.</li>
         *     <li>Generates a new secure-random Content Encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated Content Encryption {@code SecretKey} with the {@code A128KW} key wrap
         *      algorithm using the 128-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     Content Encryption {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated
         *     {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required PBKDF2 input salt from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1">&quot;p2s&quot;
         *     (PBES2 Salt Input) Header Parameter</a></li>
         *     <li>Obtains the required PBKDF2 iteration count from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">&quot;p2c&quot;
         *     (PBES2 Count) Header Parameter</a></li>
         *     <li>Derives the 128-bit Key Encryption Key with the PBES2-HS256 password-based key derivation algorithm,
         *     using the provided password, obtained salt input, and obtained iteration count as arguments.</li>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with with the {@code A128KW} key unwrap
         *      algorithm using the 128-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<Password, Password> PBES2_HS256_A128KW = Jwts.get(REGISTRY, "PBES2-HS256+A128KW");

        /**
         * Key encryption algorithm using <code>PBES2 with HMAC SHA-384 and &quot;A192KW&quot; wrapping</code>
         * as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8">RFC 7518 (JWA), Section 4.8</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Determines the number of PBDKF2 iterations via the JWE header's
         *     {@link JweHeader#getPbes2Count() pbes2Count} value.  If that value is not set, a suitable number of
         *     iterations will be chosen based on
         *     <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">OWASP
         *     PBKDF2 recommendations</a> and then that value is set as the JWE header {@code pbes2Count} value.</li>
         *     <li>Generates a new secure-random salt input and sets it as the JWE header
         *     {@link JweHeader#getPbes2Salt() pbes2Salt} value.</li>
         *     <li>Derives a 192-bit Key Encryption Key with the PBES2-HS384 password-based key derivation algorithm,
         *     using the provided password, iteration count, and input salt as arguments.</li>
         *     <li>Generates a new secure-random Content Encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated Content Encryption {@code SecretKey} with the {@code A192KW} key wrap
         *      algorithm using the 192-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     Content Encryption {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated
         *     {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required PBKDF2 input salt from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1">&quot;p2s&quot;
         *     (PBES2 Salt Input) Header Parameter</a></li>
         *     <li>Obtains the required PBKDF2 iteration count from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">&quot;p2c&quot;
         *     (PBES2 Count) Header Parameter</a></li>
         *     <li>Derives the 192-bit Key Encryption Key with the PBES2-HS384 password-based key derivation algorithm,
         *     using the provided password, obtained salt input, and obtained iteration count as arguments.</li>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with with the {@code A192KW} key unwrap
         *      algorithm using the 192-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<Password, Password> PBES2_HS384_A192KW = Jwts.get(REGISTRY, "PBES2-HS384+A192KW");

        /**
         * Key encryption algorithm using <code>PBES2 with HMAC SHA-512 and &quot;A256KW&quot; wrapping</code>
         * as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8">RFC 7518 (JWA), Section 4.8</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Determines the number of PBDKF2 iterations via the JWE header's
         *     {@link JweHeader#getPbes2Count() pbes2Count} value.  If that value is not set, a suitable number of
         *     iterations will be chosen based on
         *     <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">OWASP
         *     PBKDF2 recommendations</a> and then that value is set as the JWE header {@code pbes2Count} value.</li>
         *     <li>Generates a new secure-random salt input and sets it as the JWE header
         *     {@link JweHeader#getPbes2Salt() pbes2Salt} value.</li>
         *     <li>Derives a 256-bit Key Encryption Key with the PBES2-HS512 password-based key derivation algorithm,
         *     using the provided password, iteration count, and input salt as arguments.</li>
         *     <li>Generates a new secure-random Content Encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated Content Encryption {@code SecretKey} with the {@code A256KW} key wrap
         *      algorithm using the 256-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     Content Encryption {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated
         *     {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required PBKDF2 input salt from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1">&quot;p2s&quot;
         *     (PBES2 Salt Input) Header Parameter</a></li>
         *     <li>Obtains the required PBKDF2 iteration count from the
         *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">&quot;p2c&quot;
         *     (PBES2 Count) Header Parameter</a></li>
         *     <li>Derives the 256-bit Key Encryption Key with the PBES2-HS512 password-based key derivation algorithm,
         *     using the provided password, obtained salt input, and obtained iteration count as arguments.</li>
         *     <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with with the {@code A256KW} key unwrap
         *      algorithm using the 256-bit derived password-based Key Encryption Key from step {@code #3},
         *      producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<Password, Password> PBES2_HS512_A256KW = Jwts.get(REGISTRY, "PBES2-HS512+A256KW");

        /**
         * Key Encryption with {@code RSAES-PKCS1-v1_5}, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.2">RFC 7518 (JWA), Section 4.2</a>.
         * This algorithm requires a key size of 2048 bits or larger.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the RSA key wrap algorithm, using the JWE
         *     recipient's RSA Public Key, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the RSA key unwrap algorithm, using the JWE recipient's
         *     RSA Private Key, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> RSA1_5 = Jwts.get(REGISTRY, "RSA1_5");

        /**
         * Key Encryption with {@code RSAES OAEP using default parameters}, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3">RFC 7518 (JWA), Section 4.3</a>.
         * This algorithm requires a key size of 2048 bits or larger.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the RSA OAEP with SHA-1 and MGF1 key wrap algorithm,
         *     using the JWE recipient's RSA Public Key, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the RSA OAEP with SHA-1 and MGF1 key unwrap algorithm,
         *     using the JWE recipient's RSA Private Key, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> RSA_OAEP = Jwts.get(REGISTRY, "RSA-OAEP");

        /**
         * Key Encryption with {@code RSAES OAEP using SHA-256 and MGF1 with SHA-256}, as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3">RFC 7518 (JWA), Section 4.3</a>.
         * This algorithm requires a key size of 2048 bits or larger.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the RSA OAEP with SHA-256 and MGF1 key wrap
         *     algorithm, using the JWE recipient's RSA Public Key, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
         *     <li>Decrypts the encrypted key ciphertext with the RSA OAEP with SHA-256 and MGF1 key unwrap algorithm,
         *     using the JWE recipient's RSA Private Key, producing the decryption key plaintext.</li>
         *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> RSA_OAEP_256 = Jwts.get(REGISTRY, "RSA-OAEP-256");

        /**
         * Key Agreement with {@code ECDH-ES using Concat KDF} as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6">RFC 7518 (JWA), Section 4.6</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random Elliptic Curve public/private key pair on the same curve as the
         *     JWE recipient's EC Public Key.</li>
         *     <li>Generates a shared secret with the ECDH key agreement algorithm using the generated EC Private Key
         *     and the JWE recipient's EC Public Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> a symmetric Content
         *     Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *     generated shared secret and any available
         *     {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *     {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *     <li>Sets the generated EC key pair's Public Key as the required
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a> to be transmitted in the JWE.</li>
         *     <li>Returns the derived symmetric {@code SecretKey} for JJWT to use to encrypt the entire JWE with the
         *     associated {@link AeadAlgorithm}. Encrypted key ciphertext is not produced with this algorithm, so
         *     the resulting JWE will not contain any embedded key ciphertext.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required ephemeral Elliptic Curve Public Key from the
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a>.</li>
         *     <li>Validates that the ephemeral Public Key is on the same curve as the recipient's EC Private Key.</li>
         *     <li>Obtains the shared secret with the ECDH key agreement algorithm using the obtained EC Public Key
         *      and the JWE recipient's EC Private Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> the symmetric Content
         *      Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *      obtained shared secret and any available
         *      {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *      {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *      <li>Returns the derived symmetric {@code SecretKey} for JJWT to use to decrypt the entire
         *      JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> ECDH_ES = Jwts.get(REGISTRY, "ECDH-ES");

        /**
         * Key Agreement with Key Wrapping via
         * <code>ECDH-ES using Concat KDF and CEK wrapped with &quot;A128KW&quot;</code> as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6">RFC 7518 (JWA), Section 4.6</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random Elliptic Curve public/private key pair on the same curve as the
         *     JWE recipient's EC Public Key.</li>
         *     <li>Generates a shared secret with the ECDH key agreement algorithm using the generated EC Private Key
         *     and the JWE recipient's EC Public Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> a 128-bit symmetric Key
         *     Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *     generated shared secret and any available
         *     {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *     {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *     <li>Sets the generated EC key pair's Public Key as the required
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a> to be transmitted in the JWE.</li>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the {@code A128KW} key wrap
         *      algorithm using the derived symmetric Key Encryption Key from step {@code #3}, producing encrypted key ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required ephemeral Elliptic Curve Public Key from the
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a>.</li>
         *     <li>Validates that the ephemeral Public Key is on the same curve as the recipient's EC Private Key.</li>
         *     <li>Obtains the shared secret with the ECDH key agreement algorithm using the obtained EC Public Key
         *      and the JWE recipient's EC Private Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> the symmetric Key
         *      Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *      obtained shared secret and any available
         *      {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *      {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *      <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *      <li>Decrypts the encrypted key ciphertext with the AES Key Unwrap algorithm using the
         *      128-bit derived symmetric key from step {@code #4}, producing the decryption key plaintext.</li>
         *      <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *      JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> ECDH_ES_A128KW = Jwts.get(REGISTRY, "ECDH-ES+A128KW");

        /**
         * Key Agreement with Key Wrapping via
         * <code>ECDH-ES using Concat KDF and CEK wrapped with &quot;A192KW&quot;</code> as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6">RFC 7518 (JWA), Section 4.6</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random Elliptic Curve public/private key pair on the same curve as the
         *     JWE recipient's EC Public Key.</li>
         *     <li>Generates a shared secret with the ECDH key agreement algorithm using the generated EC Private Key
         *     and the JWE recipient's EC Public Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> a 192-bit symmetric Key
         *     Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *     generated shared secret and any available
         *     {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *     {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *     <li>Sets the generated EC key pair's Public Key as the required
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a> to be transmitted in the JWE.</li>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the {@code A192KW} key wrap
         *      algorithm using the derived symmetric Key Encryption Key from step {@code #3}, producing encrypted key
         *      ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required ephemeral Elliptic Curve Public Key from the
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a>.</li>
         *     <li>Validates that the ephemeral Public Key is on the same curve as the recipient's EC Private Key.</li>
         *     <li>Obtains the shared secret with the ECDH key agreement algorithm using the obtained EC Public Key
         *      and the JWE recipient's EC Private Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> the 192-bit symmetric
         *      Key Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *      obtained shared secret and any available
         *      {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *      {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *      <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *      <li>Decrypts the encrypted key ciphertext with the AES Key Unwrap algorithm using the
         *      192-bit derived symmetric key from step {@code #4}, producing the decryption key plaintext.</li>
         *      <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *      JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> ECDH_ES_A192KW = Jwts.get(REGISTRY, "ECDH-ES+A192KW");

        /**
         * Key Agreement with Key Wrapping via
         * <code>ECDH-ES using Concat KDF and CEK wrapped with &quot;A256KW&quot;</code> as defined by
         * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6">RFC 7518 (JWA), Section 4.6</a>.
         *
         * <p>During JWE creation, this algorithm:</p>
         * <ol>
         *     <li>Generates a new secure-random Elliptic Curve public/private key pair on the same curve as the
         *     JWE recipient's EC Public Key.</li>
         *     <li>Generates a shared secret with the ECDH key agreement algorithm using the generated EC Private Key
         *     and the JWE recipient's EC Public Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> a 256-bit symmetric Key
         *     Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *     generated shared secret and any available
         *     {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *     {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *     <li>Sets the generated EC key pair's Public Key as the required
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a> to be transmitted in the JWE.</li>
         *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
         *      specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#key()}).</li>
         *     <li>Encrypts this newly-generated {@code SecretKey} with the {@code A256KW} key wrap
         *      algorithm using the derived symmetric Key Encryption Key from step {@code #3}, producing encrypted key
         *      ciphertext.</li>
         *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
         *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
         * </ol>
         * <p>For JWE decryption, this algorithm:</p>
         * <ol>
         *     <li>Obtains the required ephemeral Elliptic Curve Public Key from the
         *      <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">&quot;epk&quot;
         *      (Ephemeral Public Key) Header Parameter</a>.</li>
         *     <li>Validates that the ephemeral Public Key is on the same curve as the recipient's EC Private Key.</li>
         *     <li>Obtains the shared secret with the ECDH key agreement algorithm using the obtained EC Public Key
         *      and the JWE recipient's EC Private Key.</li>
         *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2">Derives</a> the 256-bit symmetric
         *      Key Encryption {@code SecretKey} with the Concat KDF algorithm using the
         *      obtained shared secret and any available
         *      {@link JweHeader#getAgreementPartyUInfo() PartyUInfo} and
         *      {@link JweHeader#getAgreementPartyVInfo() PartyVInfo}.</li>
         *      <li>Obtains the encrypted key ciphertext embedded in the received JWE.</li>
         *      <li>Decrypts the encrypted key ciphertext with the AES Key Unwrap algorithm using the
         *      256-bit derived symmetric key from step {@code #4}, producing the decryption key plaintext.</li>
         *      <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
         *      JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}.</li>
         * </ol>
         */
        public static final KeyAlgorithm<PublicKey, PrivateKey> ECDH_ES_A256KW = Jwts.get(REGISTRY, "ECDH-ES+A256KW");

        //prevent instantiation
        private KEY() {
        }
    }

    /**
     * Constants for JWA (RFC 7518) compression algorithms referenced in the {@code zip} header defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.3">JSON Web Encryption Compression Algorithms
     * Registry</a>. Each algorithm is available as a ({@code public static final}) constant for
     * direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .compressWith(<b>Jwts.ZIP.DEF</b>)
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #get()} method.</p>
     *
     * @see #get()
     * @since JJWT_RELEASE_VERSION
     */
    public static final class ZIP {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.io.StandardCompressionAlgorithms";
        private static final Registry<String, CompressionAlgorithm> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns various useful <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.3">
         * Compression Algorithms</a>.
         *
         * @return various standard and non-standard useful compression algorithms.
         */
        public static Registry<String, CompressionAlgorithm> get() {
            return REGISTRY;
        }

        /**
         * The JWE-standard <a href="https://www.rfc-editor.org/rfc/rfc1951">DEFLATE</a>
         * compression algorithm with a {@code zip} header value of {@code "DEF"}.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3">JWE RFC 7516, Section 4.1.3</a>
         */
        public static final CompressionAlgorithm DEF = get().forKey("DEF");

        /**
         * A commonly used, but <b>NOT JWA-STANDARD</b>
         * <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a> compression algorithm with a {@code zip} header value
         * of {@code "GZIP"}.
         *
         * <p><b>Compatibility Warning</b></p>
         *
         * <p><b>This is not a standard JWE compression algorithm</b>.  Be sure to use this only when you are confident
         * that all parties accessing the token support the &quot;GZIP&quot; identifier and associated algorithm.</p>
         *
         * <p>If you're concerned about compatibility, {@link #DEF DEF} is the only JWA standards-compliant algorithm.</p>
         *
         * @see #DEF
         */
        public static final CompressionAlgorithm GZIP = get().forKey("GZIP");

        //prevent instantiation
        private ZIP() {
        }
    }

    /**
     * A {@link Builder} that dynamically determines the type of {@link Header} to create based on builder state.
     *
     * @since JJWT_RELEASE_VERSION
     */
    public interface HeaderBuilder extends JweHeaderMutator<HeaderBuilder>, X509Builder<HeaderBuilder>, Builder<Header> {
    }

    /**
     * Returns a new {@link HeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     *
     * @return a new {@link HeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     * @since JJWT_RELEASE_VERSION
     */
    public static HeaderBuilder header() {
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
     * {@code Jwts.}{@link #claims()}{@code .add(map).build()}</b>.
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
        return claims().add(claims).build();
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

    /**
     * Returns a new {@link JwtParserBuilder} instance that can be configured to create an immutable/thread-safe {@link JwtParser}.
     *
     * @return a new {@link JwtParser} instance that can be configured create an immutable/thread-safe {@link JwtParser}.
     */
    public static JwtParserBuilder parser() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParserBuilder");
    }

    /**
     * Private constructor, prevent instantiation.
     */
    private Jwts() {
    }
}

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
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecretKeyAlgorithm;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

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
     * Constants for all standard JWA (RFC 7518) <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">
     * Cryptographic Algorithms for Key Management</a>. Each standard algorithm is available as a
     * ({@code public static final}) constant for direct type-safe reference in application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwe.enc.ECDH_ES_A256KW</b>, Jwe.alg.A256GCM)
     *    .build();</pre></blockquote>
     * <p>They are also available together as a {@link Registry} instance via the {@link #registry()} method.</p>
     *
     * @see #registry()
     * @since JJWT_RELEASE_VERSION
     */
    final class enc {

        private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardKeyAlgorithms";
        private static final Registry<String, KeyAlgorithm<?, ?>> REGISTRY = Classes.newInstance(IMPL_CLASSNAME);

        /**
         * Returns all standard JWA standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">Cryptographic
         * Algorithms for Key Management</a>..
         *
         * @return all standard JWA Key Management algorithms.
         */
        public static Registry<String, KeyAlgorithm<?, ?>> registry() {
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
        private enc() {
        }
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

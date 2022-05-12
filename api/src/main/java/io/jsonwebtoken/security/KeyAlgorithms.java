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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.util.Collection;

/**
 * Constant definitions and utility methods for all
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4">JWA (RFC 7518) Key Management Algorithms</a>.
 *
 * @see #values() 
 * @see #findById(String) 
 * @see #forId(String) 
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("rawtypes")
public final class KeyAlgorithms {

    //prevent instantiation
    private KeyAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeyAlgorithmsBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};
    //private static final Class<?>[] ESTIMATE_ITERATIONS_ARG_TYPES = new Class[]{KeyAlgorithm.class, long.class};

    public static Collection<KeyAlgorithm<?, ?>> values() {
        return Classes.invokeStatic(BRIDGE_CLASS, "values", null, (Object[]) null);
    }

    /**
     * Returns the JWE KeyAlgorithm with the specified
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">{@code alg} key algorithm identifier</a> or
     * {@code null} if an algorithm for the specified {@code id} cannot be found.
     *
     * @param id a JWE standard {@code alg} key algorithm identifier
     * @return the associated KeyAlgorithm instance or {@code null} otherwise.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">RFC 7518, Section 4.1</a>
     */
    public static KeyAlgorithm<?, ?> findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "findById", ID_ARG_TYPES, id);
    }

    public static KeyAlgorithm<?, ?> forId(String id) {
        return forId0(id);
    }

    // do not change this visibility.  Raw type method signature not be publicly exposed
    private static <T> T forId0(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "forId", ID_ARG_TYPES, id);
    }

    /**
     * Key algorithm reflecting direct use of a shared symmetric key as the JWE AEAD encryption key, as defined
     * by <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.5">RFC 7518 (JWA), Section 4.5</a>.  This
     * algorithm does not produce encrypted key ciphertext.
     */
    public static final KeyAlgorithm<SecretKey, SecretKey> DIRECT = forId0("dir");

    /**
     * AES Key Wrap algorithm with default initial value using a 128-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 128-bit shared symmetric key using the
     *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Decrypts the encrypted key ciphertext with the 128-bit shared symmetric key,
     *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A128KW = forId0("A128KW");

    /**
     * AES Key Wrap algorithm with default initial value using a 192-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 192-bit shared symmetric key using the
     *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Decrypts the encrypted key ciphertext with the 192-bit shared symmetric key,
     *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A192KW = forId0("A192KW");

    /**
     * AES Key Wrap algorithm with default initial value using a 256-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.4">RFC 7518 (JWA), Section 4.4</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 256-bit shared symmetric key using the
     *     AES Key Wrap algorithm, producing encrypted key ciphertext.</li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Decrypts the encrypted key ciphertext with the 256-bit shared symmetric key,
     *     using the AES Key Unwrap algorithm, producing the decryption key plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A256KW = forId0("A256KW");

    /**
     * Key wrap algorithm with AES GCM using a 128-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 128-bit shared symmetric key using the
     *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
     *     and GCM authentication tag.</li>
     *     <li>Sets the generated initialization vector as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Sets the resulting GCM authentication tag as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Obtains the required initialization vector from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Obtains the required GCM authentication tag from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Decrypts the encrypted key ciphertext with the 128-bit shared symmetric key, the initialization vector
     *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key
     *     plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A128GCMKW = forId0("A128GCMKW");

    /**
     * Key wrap algorithm with AES GCM using a 192-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 192-bit shared symmetric key using the
     *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
     *     and GCM authentication tag.</li>
     *     <li>Sets the generated initialization vector as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Sets the resulting GCM authentication tag as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Obtains the required initialization vector from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Obtains the required GCM authentication tag from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Decrypts the encrypted key ciphertext with the 192-bit shared symmetric key, the initialization vector
     *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key \
     *     plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A192GCMKW = forId0("A192GCMKW");

    /**
     * Key wrap algorithm with AES GCM using a 256-bit key, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
     *
     * <p>During JWE creation, this algorithm:</p>
     * <ol>
     *     <li>Generates a new secure-random content encryption {@link SecretKey} suitable for use with a
     *     specified {@link AeadAlgorithm} (using {@link AeadAlgorithm#keyBuilder()}).</li>
     *     <li>Generates a new secure-random 96-bit Initialization Vector to use during key wrap/encryption.</li>
     *     <li>Encrypts this newly-generated {@code SecretKey} with a 256-bit shared symmetric key using the
     *     AES GCM Key Wrap algorithm with the generated Initialization Vector, producing encrypted key ciphertext
     *     and GCM authentication tag.</li>
     *     <li>Sets the generated initialization vector as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Sets the resulting GCM authentication tag as the required
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Returns the encrypted key ciphertext for inclusion in the final JWE as well as the newly-generated
     *     {@code SecretKey} for JJWT to use to encrypt the entire JWE with associated {@link AeadAlgorithm}.</li>
     * </ol>
     * <p>For JWE decryption, this algorithm:</p>
     * <ol>
     *     <li>Receives the encrypted key ciphertext embedded in the received JWE.</li>
     *     <li>Obtains the required initialization vector from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">&quot;iv&quot;
     *     (Initialization Vector) Header Parameter</a></li>
     *     <li>Obtains the required GCM authentication tag from the
     *     <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">&quot;tag&quot;
     *     (Authentication Tag) Header Parameter</a></li>
     *     <li>Decrypts the encrypted key ciphertext with the 256-bit shared symmetric key, the initialization vector
     *     and GCM authentication tag using the AES GCM Key Unwrap algorithm, producing the decryption key \
     *     plaintext.</li>
     *     <li>Returns the decryption key plaintext as a {@link SecretKey} for JJWT to use to decrypt the entire
     *     JWE using the JWE's identified &quot;enc&quot; {@link AeadAlgorithm}. </li>
     * </ol>
     */
    public static final SecretKeyAlgorithm A256GCMKW = forId0("A256GCMKW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS256_A128KW = forId0("PBES2-HS256+A128KW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS384_A192KW = forId0("PBES2-HS384+A192KW");
    public static final KeyAlgorithm<PasswordKey, PasswordKey> PBES2_HS512_A256KW = forId0("PBES2-HS512+A256KW");

    /**
     * Key Encryption with RSAES-PKCS1-v1_5, as defined by
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7">RFC 7518 (JWA), Section 4.7</a>.
     */
    public static final RsaKeyAlgorithm RSA1_5 = forId0("RSA1_5");
    public static final RsaKeyAlgorithm RSA_OAEP = forId0("RSA-OAEP");
    public static final RsaKeyAlgorithm RSA_OAEP_256 = forId0("RSA-OAEP-256");
    public static final EcKeyAlgorithm ECDH_ES = forId0("ECDH-ES");
    public static final EcKeyAlgorithm ECDH_ES_A128KW = forId0("ECDH-ES+A128KW");
    public static final EcKeyAlgorithm ECDH_ES_A192KW = forId0("ECDH-ES+A192KW");
    public static final EcKeyAlgorithm ECDH_ES_A256KW = forId0("ECDH-ES+A256KW");

    /*
    public static int estimateIterations(KeyAlgorithm<PasswordKey, PasswordKey> alg, long desiredMillis) {
        return Classes.invokeStatic(BRIDGE_CLASS, "estimateIterations", ESTIMATE_ITERATIONS_ARG_TYPES, alg, desiredMillis);
    }
     */
}

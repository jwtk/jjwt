/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Registry;

/**
 * Standard JSON Web Token algorithm implementations organized by algorithm type.  Each organized collection of
 * algorithms is available via a static field to allow for easy code-completion in IDEs, showing available
 * algorithm instances, for example, when typing:
 *
 * <blockquote><pre>
 *     Algorithms.// press code-completion hotkeys to suggest available algorithm registry fields
 *     Algorithms.sig.// press hotkeys to suggest individual Digital Signature or MAC algorithms or utility methods
 *     Algorithms.enc.// press hotkeys to suggest individual encryption algorithms or utility methods
 *     Algorithms.key.// press hotkeys to suggest individual key algorithms or utility methods
 *     Algorithms.hash.// press hotkeys to suggest individual hash algorithms or utility methods
 * </pre></blockquote>
 *
 * @see Algorithms#enc
 * @see Algorithms#hash
 * @see Algorithms#key
 * @see Algorithms#sig
 * @since JJWT_RELEASE_VERSION
 */
public final class Algorithms {

    /**
     * Prevent instantiation
     */
    private Algorithms() {
        throw new AssertionError("io.jsonwebtoken.security.Algorithms may not be instantiated.");
    }

    /**
     * Registry of various (<em>but not all</em>)
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
     * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.  For
     * example:
     * <blockquote><pre>
     * Jwks.{@link  JwkBuilder builder}()
     *     // ... etc ...
     *     .{@link JwkBuilder#setIdFromThumbprint(HashAlgorithm) setIdFromThumbprint}(Algorithms.hash.{@link StandardHashAlgorithms#SHA256 SHA256}) // &lt;---
     *     .build()</pre></blockquote>
     * <p>or</p>
     * <blockquote><pre>
     * HashAlgorithm hashAlg = Algorithms.hash.{@link StandardHashAlgorithms#SHA256 SHA256};
     * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
     * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
     * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
     * </pre></blockquote>
     *
     * @see HashAlgorithm
     * @see HashAlgorithm#getId()
     * @see StandardHashAlgorithms
     * @see Registry
     */
    public static final StandardHashAlgorithms hash = StandardHashAlgorithms.get();

    /**
     * {@link Registry} for all standard
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWA (RFC 7518) Encryption Algorithms</a>. In
     * addition to being available via registry {@link StandardEncryptionAlgorithms#get(String) get} and
     * {@link StandardEncryptionAlgorithms#find(String) find} lookup methods, each algorithm is also available as a
     * ({@code public final}) constant for direct type-safe reference in application code.  For example:
     * <blockquote><pre>
     * Jwts.builder()
     *     // ... etc ...
     *     .encryptWith(secretKey, <b>Algorithms.enc.A256GCM</b>) // or A128GCM, A192GCM, etc...
     *     .build();</pre></blockquote>
     * <p>Direct type-safe references as shown above are often better than calling
     * {@link StandardEncryptionAlgorithms#get(String) get} or {@link StandardEncryptionAlgorithms#find(String) find}
     * with potentially misspelled or otherwise invalid string identifiers.</p>
     *
     * @see AeadAlgorithm
     * @see AeadAlgorithm#getId()
     * @see StandardEncryptionAlgorithms
     */
    public static final StandardEncryptionAlgorithms enc = StandardEncryptionAlgorithms.get();

    /**
     * Registry of all standard JWE Key Management Algorithms defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">JWA (RFC 7518) Key Management Algorithms</a>
     * and formalized in <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">
     * JSON Web Signature and Encryption Algorithms Registry</a>.  The variable is named &quot;{@code alg}&quot; for two
     * reasons:
     * <ul>
     *     <li>The variable name equals the name of the JWE header that contains the key management algorithm
     *     {@link KeyAlgorithm#getId() identifier} values, self-documenting its purpose in referenced code.</li>
     *     <li>It is short and simpler to reference {@code Jwe.alg.A256GCMKW} in application
     *     code instead of the more verbose static class variable alternative of, say,
     *     {@code StandardKeyAlgorithms.A256GCMKW}. For example:
     * <blockquote><pre>Jwts.builder()...
     *   .encryptWith(secretKey, Jwe.alg.A256GCMKW, Jwe.enc.A256GCM)
     *   //.encryptWith(secretKey, StandardKeyAlgorithms.A256GCMKW, StandardEncryptionAlgorithms...
     *   .build();</pre></blockquote>
     *     </li>
     * </ul>
     *
     * @see KeyAlgorithm
     * @see KeyAlgorithm#getId()
     */
    public static final StandardKeyAlgorithms key = StandardKeyAlgorithms.get();

    /**
     * Registry of all standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS Digital
     * Signature and MAC Algorithms</a> codified in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption Algorithms
     * Registry</a>.
     *
     * @see StandardSecureDigestAlgorithms
     * @see SecureDigestAlgorithm
     * @see MacAlgorithm
     * @see SignatureAlgorithm
     */
    public static final StandardSecureDigestAlgorithms sig = StandardSecureDigestAlgorithms.get();

}

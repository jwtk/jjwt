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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;

import java.security.Key;
import java.util.Collection;

/**
 * Registry of all standard JWS
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic Algorithms for Digital
 * Signatures and MACs</a>. These are most commonly accessed via the {@link io.jsonwebtoken.Jwts#SIG} convenience
 * alias when creating a JWS.  For example:
 * <blockquote><pre>
 * {@link Jwts#builder()}.
 *     // ... etc ...
 *     .{@link io.jsonwebtoken.JwtBuilder#signWith(Key, SecureDigestAlgorithm) signWith}(aKey, {@link Jwts#SIG}.HS256) // &lt;--
 *     .build()</pre></blockquote>
 *
 * @see #get()
 * @see #get(String)
 * @see #find(String)
 * @see #values()
 * @since JJWT_RELEASE_VERSION
 */
public final class StandardSecureDigestAlgorithms implements Registry<String, SecureDigestAlgorithm<?, ?>> {

    private static final Registry<String, SecureDigestAlgorithm<?, ?>> IMPL =
            Classes.newInstance("io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithmsBridge");

    private static final StandardSecureDigestAlgorithms INSTANCE = new StandardSecureDigestAlgorithms();

    /**
     * Returns this registry (a static singleton).
     *
     * @return this registry (a static singleton).
     */
    public static StandardSecureDigestAlgorithms get() { // named `get` to mimic java.util.function.Supplier
        return INSTANCE;
    }

    /**
     * The &quot;none&quot; signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section 3.6</a>.  This algorithm
     * is used only when creating unsecured (not integrity protected) JWSs and is not usable in any other scenario.
     * Any attempt to call its methods will result in an exception being thrown.
     */
    public final SecureDigestAlgorithm<Key, Key> NONE = doGet("none");

    /**
     * {@code HMAC using SHA-256} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 256-bit (32 byte) key.
     */
    public final MacAlgorithm HS256 = doGet("HS256");

    /**
     * {@code HMAC using SHA-384} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 384-bit (48 byte) key.
     */
    public final MacAlgorithm HS384 = doGet("HS384");

    /**
     * {@code HMAC using SHA-512} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 512-bit (64 byte) key.
     */
    public final MacAlgorithm HS512 = doGet("HS512");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key.
     */
    public final SignatureAlgorithm RS256 = doGet("RS256");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
     */
    public final SignatureAlgorithm RS384 = doGet("RS384");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
     */
    public final SignatureAlgorithm RS512 = doGet("RS512");

    /**
     * {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final SignatureAlgorithm PS256 = doGet("PS256");

    /**
     * {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final SignatureAlgorithm PS384 = doGet("PS384");

    /**
     * {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final SignatureAlgorithm PS512 = doGet("PS512");

    /**
     * {@code ECDSA using P-256 and SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 256-bit key.
     */
    public final SignatureAlgorithm ES256 = doGet("ES256");

    /**
     * {@code ECDSA using P-384 and SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 384-bit key.
     */
    public final SignatureAlgorithm ES384 = doGet("ES384");

    /**
     * {@code ECDSA using P-521 and SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 521-bit key.
     */
    public final SignatureAlgorithm ES512 = doGet("ES512");

    /**
     * {@code EdDSA} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires either {@code Ed25519} or {@code Ed448} Edwards Curve keys.
     * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final SignatureAlgorithm EdDSA = doGet("EdDSA");

    /**
     * {@code EdDSA} signature algorithm using Curve {@code Ed25519} as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires {@code Ed25519} Edwards Curve keys to create signatures.  <b>This is a convenience alias for
     * {@link #EdDSA}</b> that defaults key generation to {@code Ed25519} keys.
     * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final SignatureAlgorithm Ed25519 = doGet("Ed25519");

    /**
     * {@code EdDSA} signature algorithm using Curve {@code Ed448} as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires {@code Ed448} Edwards Curve keys to create signatures. <b>This is a convenience alias for
     * {@link #EdDSA}</b> that defaults key generation to {@code Ed448} keys.
     * <p><b>This algorithm requires at least JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final SignatureAlgorithm Ed448 = doGet("Ed448");

    /**
     * Prevent external instantiation.
     */
    private StandardSecureDigestAlgorithms() {
    }

    // do not change this visibility.  Raw type method signature not be publicly exposed
    @SuppressWarnings("unchecked")
    private <T> T doGet(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return (T) get(id);
    }

    /**
     * Returns all standard JWS
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">Digital Signature and MAC Algorithms</a>
     * as an unmodifiable collection.
     *
     * @return all standard JWS
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">Digital Signature and MAC Algorithms</a>
     * as an unmodifiable collection.
     */
    public Collection<SecureDigestAlgorithm<?, ?>> values() {
        return IMPL.values();
    }

    /**
     * Returns the {@link SignatureAlgorithm} or {@link MacAlgorithm} instance with the specified
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">{@code alg} algorithm identifier</a> or
     * {@code null} if an algorithm for the specified {@code id} cannot be found.  If a JWA-standard
     * instance must be resolved, consider using the {@link #get(String)} method instead.
     *
     * @param id a JWA-standard identifier defined in
     *           <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWA RFC 7518, Section 3.1</a>
     *           in the <code>&quot;alg&quot; Param Value</code> column.
     * @return the {@code SecureDigestAlgorithm} instance with the specified JWA-standard identifier, or
     * {@code null} if no algorithm with that identifier exists.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">RFC 7518, Section 3.1</a>
     * @see #get(String)
     */
    public SecureDigestAlgorithm<?, ?> find(String id) {
        return IMPL.find(id);
    }

    /**
     * Returns the {@link SignatureAlgorithm} or {@link MacAlgorithm} instance with the specified
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">{@code alg} algorithm identifier</a> or
     * throws an {@link IllegalArgumentException} if there is no JWA-standard algorithm for the specified
     * {@code id}.  If a JWA-standard instance result is not mandatory, consider using the {@link #find(String)}
     * method instead.
     *
     * @param id a JWA-standard identifier defined in
     *           <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWA RFC 7518, Section 3.1</a>
     *           in the <code>&quot;alg&quot; Param Value</code> column.
     * @return the associated {@code SecureDigestAlgorithm} instance.
     * @throws IllegalArgumentException if there is no JWA-standard algorithm for the specified identifier.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">RFC 7518, Section 3.1</a>
     * @see #find(String)
     */
    public SecureDigestAlgorithm<?, ?> get(String id) throws IllegalArgumentException {
        return IMPL.get(id);
    }
}

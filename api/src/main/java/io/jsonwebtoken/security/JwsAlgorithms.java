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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.security.Key;
import java.util.Collection;

/**
 * Constant definitions and utility methods for JWS standard
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic Algorithms for Digital Signatures and
 * MACs</a>.
 *
 * @since JJWT_RELEASE_VERSION
 */
public final class JwsAlgorithms {

    // Prevent instantiation
    private JwsAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.JwsAlgorithmsBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};

    /**
     * Returns all JWA-standard {@code SecureDigestAlgorithm}s as an unmodifiable collection.
     *
     * @return all JWA-standard {@code SecureDigestAlgorithm}s as an unmodifiable collection.
     */
    public static Collection<SecureDigestAlgorithm<?, ?>> values() {
        return Classes.invokeStatic(BRIDGE_CLASS, "values", null, (Object[]) null);
    }

    /**
     * Returns the {@code SecureDigestAlgorithm} instance with the specified JWA-standard identifier, or
     * {@code null} if no algorithm with that identifier exists.  If a result is mandatory, consider using
     * {@link #forId(String)} instead.
     *
     * @param id a JWA-standard identifier defined in
     *           <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWA RFC 7518, Section 3.1</a>
     *           in the <code>&quot;alg&quot; Param Value</code> column.
     * @return the {@code SecureDigestAlgorithm} instance with the specified JWA-standard identifier, or
     * {@code null} if no algorithm with that identifier exists.
     * @see #forId(String)
     */
    public static SecureDigestAlgorithm<?, ?> findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "findById", ID_ARG_TYPES, id);
    }

    /**
     * Returns the {@code SecureDigestAlgorithm} instance with the specified JWA-standard identifier, or
     * throws an {@link IllegalArgumentException} if there is no such JWA-standard signature algorithm identifier.
     * If a result is not mandatory, consider using {@link #findById(String)} instead.
     *
     * @param id a JWA-standard identifier defined in
     *           <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWA RFC 7518, Section 3.1</a>
     *           in the <code>&quot;alg&quot; Param Value</code> column.
     * @return the {@code SecureDigestAlgorithm} instance with the specified JWA-standard identifier
     * @throws IllegalArgumentException is {@code id} is not a JWA-standard signature algorithm identifier.
     * @see #findById(String)
     */
    public static SecureDigestAlgorithm<?, ?> forId(String id) throws IllegalArgumentException {
        return forId0(id);
    }

    static <T> T forId0(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "forId", ID_ARG_TYPES, id);
    }

    /**
     * The &quot;none&quot; signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section 3.6</a>.  This algorithm
     * is used only when creating unsecured (not integrity protected) JWSs and is not usable in any other scenario.
     * Any attempt to call its methods will result in an exception being thrown.
     */
    public static final SecureDigestAlgorithm<Key, Key> NONE = forId0("none");

    /**
     * {@code HMAC using SHA-256} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 256-bit (32 byte) key.
     */
    public static final MacAlgorithm HS256 = forId0("HS256");

    /**
     * {@code HMAC using SHA-384} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 384-bit (48 byte) key.
     */
    public static final MacAlgorithm HS384 = forId0("HS384");

    /**
     * {@code HMAC using SHA-512} message authentication algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2">RFC 7518, Section 3.2</a>.  This algorithm
     * requires a 512-bit (64 byte) key.
     */
    public static final MacAlgorithm HS512 = forId0("HS512");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key.
     */
    public static final SignatureAlgorithm RS256 = forId0("RS256");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
     */
    public static final SignatureAlgorithm RS384 = forId0("RS384");

    /**
     * {@code RSASSA-PKCS1-v1_5 using SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">RFC 7518, Section 3.3</a>.  This algorithm
     * requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
     */
    public static final SignatureAlgorithm RS512 = forId0("RS512");

    /**
     * {@code RSASSA-PSS using SHA-256 and MGF1 with SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final SignatureAlgorithm PS256 = forId0("PS256");

    /**
     * {@code RSASSA-PSS using SHA-384 and MGF1 with SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key, but the JJWT team recommends a 3072-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final SignatureAlgorithm PS384 = forId0("PS384");

    /**
     * {@code RSASSA-PSS using SHA-512 and MGF1 with SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5">RFC 7518, Section 3.5</a><b><sup>1</sup></b>.
     * This algorithm requires a 2048-bit key, but the JJWT team recommends a 4096-bit key.
     *
     * <p><b><sup>1</sup></b> Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 10 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final SignatureAlgorithm PS512 = forId0("PS512");

    /**
     * {@code ECDSA using P-256 and SHA-256} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 256-bit key.
     */
    public static final SignatureAlgorithm ES256 = forId0("ES256");

    /**
     * {@code ECDSA using P-384 and SHA-384} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 384-bit key.
     */
    public static final SignatureAlgorithm ES384 = forId0("ES384");

    /**
     * {@code ECDSA using P-521 and SHA-512} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>.  This algorithm
     * requires a 521-bit key.
     */
    public static final SignatureAlgorithm ES512 = forId0("ES512");

    /**
     * {@code EdDSA} signature algorithm as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires either {@code Ed25519} or {@code Ed448} Edwards Curve keys.
     */
    public static final SignatureAlgorithm EdDSA = forId0("EdDSA");

    /**
     * {@code EdDSA} signature algorithm using Curve 25519 as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires {@code Ed25519} Edwards Curve keys to create signatures.
     * <p><b>This is a convenience alias for {@link #EdDSA}</b> that defaults key generation to
     * {@code Ed25519} keys.</p>
     */
    public static final SignatureAlgorithm Ed25519 = forId0("Ed25519");

    /**
     * {@code EdDSA} signature algorithm using Curve 25519 as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037, Section 3.1</a>.  This algorithm
     * requires {@code Ed448} Edwards Curve keys to create signatures.
     * <p><b>This is a convenience alias for {@link #EdDSA}</b> that defaults key generation to
     * {@code Ed448} keys.</p>
     */
    public static final SignatureAlgorithm Ed448 = forId0("Ed448");

}

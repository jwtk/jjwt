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

import java.util.Collection;

/**
 * Constant definitions and utility methods for all
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWA (RFC 7518) Encryption Algorithms</a>.
 *
 * @see AeadAlgorithm
 * @see #values()
 * @see #forId(String) 
 * @see #findById(String)
 * @since JJWT_RELEASE_VERSION
 */
public final class EncryptionAlgorithms {

    //prevent instantiation
    private EncryptionAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.EncryptionAlgorithmsBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};

    /**
     * Returns all JWE-standard AEAD encryption algorithms as an unmodifiable collection.
     *
     * @return all JWE-standard AEAD encryption algorithms as an unmodifiable collection.
     */
    public static Collection<AeadAlgorithm> values() {
        return Classes.invokeStatic(BRIDGE_CLASS, "values", null, (Object[]) null);
    }

    /**
     * Returns the JWE Encryption Algorithm with the specified
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">{@code enc} algorithm identifier</a> or
     * {@code null} if a JWE-standard algorithm for the specified {@code id} cannot be found.  If a JWE-standard
     * instance must be resolved, consider using the {@link #forId(String)} method instead.
     *
     * @param id a JWE standard {@code enc} algorithm identifier
     * @return the associated standard Encryption Algorithm instance or {@code null} otherwise.
     * @see #forId(String)
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">RFC 7518, Section 5.1</a>
     */
    public static AeadAlgorithm findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "findById", ID_ARG_TYPES, id);
    }

    /**
     * Returns the JWE Encryption Algorithm with the specified
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">{@code enc} algorithm identifier</a> or
     * throws an {@link IllegalArgumentException} if there is no JWE-standard algorithm for the specified
     * {@code id}.  If a JWE-standard instance result is not mandatory, consider using the {@link #findById(String)}
     * method instead.
     *
     * @param id a JWE standard {@code enc} algorithm identifier
     * @return the associated Encryption Algorithm instance.
     * @throws IllegalArgumentException if there is no JWE-standard algorithm for the specified identifier.
     * @see #findById(String)
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">RFC 7518, Section 5.1</a>
     */
    public static AeadAlgorithm forId(String id) throws IllegalArgumentException {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "forId", ID_ARG_TYPES, id);
    }

    /**
     * {@code AES_128_CBC_HMAC_SHA_256} authenticated encryption algorithm as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256-bit (32 byte) key.
     */
    public static final AeadAlgorithm A128CBC_HS256 = forId("A128CBC-HS256");

    /**
     * {@code AES_192_CBC_HMAC_SHA_384} authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
     * requires a 384-bit (48 byte) key.
     */
    public static final AeadAlgorithm A192CBC_HS384 = forId("A192CBC-HS384");

    /**
     * {@code AES_256_CBC_HMAC_SHA_512} authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
     * requires a 512-bit (64 byte) key.
     */
    public static final AeadAlgorithm A256CBC_HS512 = forId("A256CBC-HS512");

    /**
     * &quot;AES GCM using 128-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 128-bit (16 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final AeadAlgorithm A128GCM = forId("A128GCM");

    /**
     * &quot;AES GCM using 192-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 192-bit (24 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final AeadAlgorithm A192GCM = forId("A192GCM");

    /**
     * &quot;AES GCM using 256-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 256-bit (32 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public static final AeadAlgorithm A256GCM = forId("A256GCM");
}

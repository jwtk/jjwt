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
import io.jsonwebtoken.lang.Registry;

/**
 * {@link Registry} singleton containing all standard JWE
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">Encryption Algorithms</a>
 * codified in the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">
 * JSON Web Signature and Encryption Algorithms Registry</a>. These are most commonly accessed via the
 * {@link io.jsonwebtoken.Jwts#ENC} convenience alias when creating a JWE.  For example:
 * <blockquote><pre>
 * {@link Jwts#builder()}.
 *     // ... etc ...
 *     .encryptWith(secretKey, <b>{@link Jwts#ENC}.A256GCM</b>) // or A128GCM, A192GCM, etc...
 *     .build()</pre></blockquote>
 * <p>Direct type-safe references as shown above are often better than calling {@link #forKey(Object)} or
 * {@link Registry#get(Object)} which can be susceptible to misspelled or otherwise invalid string values.</p>
 *
 * @see #get()
 * @see #forKey(Object)
 * @see Registry#get(Object)
 * @see #values()
 * @see AeadAlgorithm
 * @since JJWT_RELEASE_VERSION
 */
public final class StandardEncryptionAlgorithms extends ImplRegistry<AeadAlgorithm> {

    private static final String IMPL_CLASSNAME = "io.jsonwebtoken.impl.security.StandardEncryptionAlgorithmsBridge";

    private static final StandardEncryptionAlgorithms INSTANCE = new StandardEncryptionAlgorithms();

    /**
     * Returns this registry (a static singleton).
     *
     * @return this registry (a static singleton).
     */
    public static StandardEncryptionAlgorithms get() { // named `get` to mimic java.util.function.Supplier
        return INSTANCE;
    }

    /**
     * {@code AES_128_CBC_HMAC_SHA_256} authenticated encryption algorithm as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256-bit (32 byte) key.
     */
    public final AeadAlgorithm A128CBC_HS256 = forKey("A128CBC-HS256");

    /**
     * {@code AES_192_CBC_HMAC_SHA_384} authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
     * requires a 384-bit (48 byte) key.
     */
    public final AeadAlgorithm A192CBC_HS384 = forKey("A192CBC-HS384");

    /**
     * {@code AES_256_CBC_HMAC_SHA_512} authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
     * requires a 512-bit (64 byte) key.
     */
    public final AeadAlgorithm A256CBC_HS512 = forKey("A256CBC-HS512");

    /**
     * &quot;AES GCM using 128-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 128-bit (16 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final AeadAlgorithm A128GCM = forKey("A128GCM");

    /**
     * &quot;AES GCM using 192-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 192-bit (24 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final AeadAlgorithm A192GCM = forKey("A192GCM");

    /**
     * &quot;AES GCM using 256-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a><b><sup>1</sup></b>.  This
     * algorithm requires a 256-bit (32 byte) key.
     *
     * <p><b><sup>1</sup></b> Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath. If on Java 7 or earlier, BouncyCastle will be used automatically if found in the runtime
     * classpath.</p>
     */
    public final AeadAlgorithm A256GCM = forKey("A256GCM");

    /**
     * Prevent external instantiation.
     */
    private StandardEncryptionAlgorithms() {
        super(IMPL_CLASSNAME);
    }
}

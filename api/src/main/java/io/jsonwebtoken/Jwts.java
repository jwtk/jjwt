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

import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.StandardEncryptionAlgorithms;
import io.jsonwebtoken.security.StandardKeyAlgorithms;
import io.jsonwebtoken.security.StandardSecureDigestAlgorithms;

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
 * Jwts.{@link #SIG}.// press hotkeys to suggest individual Digital Signature or MAC algorithms or utility methods
 * Jwts.{@link #ENC}.// press hotkeys to suggest individual encryption algorithms or utility methods
 * Jwts.{@link #KEY}.// press hotkeys to suggest individual key algorithms or utility methods</pre></blockquote>
 *
 * @since 0.1
 */
public final class Jwts {

    @SuppressWarnings("rawtypes")
    private static final Class[] MAP_ARG = new Class[]{Map.class};

    /**
     * All JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5">Cryptographic
     * Algorithms for Content Encryption</a> defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">
     * JSON Web Signature and Encryption Algorithms Registry</a>. In addition to its
     * {@link Registry#get(Object) get} and {@link Registry#find(Object) find} lookup methods, each standard algorithm
     * is also available as a ({@code public final}) constant for direct type-safe reference in application code.
     * For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.ENC.A256GCM</b>) // or A128GCM, A192GCM, etc...
     *    .build();</pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final StandardEncryptionAlgorithms ENC = StandardEncryptionAlgorithms.get();

    /**
     * All JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic
     * Algorithms for Digital Signatures and MACs</a> defined in the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1">JSON Web Signature and Encryption Algorithms
     * Registry</a>. In addition to its
     * {@link Registry#get(Object) get} and {@link Registry#find(Object) find} lookup methods, each standard algorithm
     * is also available as a ({@code public final}) constant for direct type-safe reference in application code.
     * For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .signWith(aKey, <b>Jwts.SIG.HS512</b>) // or RS512, PS256, EdDSA, etc...
     *    .build();</pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final StandardSecureDigestAlgorithms SIG = StandardSecureDigestAlgorithms.get();

    /**
     * All JWA (RFC 7518) standard <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4">Cryptographic
     * Algorithms for Key Management</a>. In addition to its
     * convenience {@link Registry#get(Object) get} and {@link Registry#find(Object) find} lookup methods, each
     * standard algorithm is also available as a ({@code public final}) constant for direct type-safe reference in
     * application code. For example:
     * <blockquote><pre>
     * Jwts.builder()
     *    // ... etc ...
     *    .encryptWith(aKey, <b>Jwts.KEY.ECDH_ES_A256KW</b>, Jwts.ENC.A256GCM)
     *    .build();</pre></blockquote>
     *
     * @since JJWT_RELEASE_VERSION
     */
    public static final StandardKeyAlgorithms KEY = StandardKeyAlgorithms.get();

    /**
     * Private constructor, prevent instantiation.
     */
    private Jwts() {
    }

    /**
     * Returns a new {@link JwtHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     *
     * @return a new {@link JwtHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     * @since JJWT_RELEASE_VERSION
     */
    public static JwtHeaderBuilder header() {
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
     * {@code Jwts.}{@link #claims()}{@code .putAll(map).build()}</b>.
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
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultClaims", MAP_ARG, claims);
    }

    /**
     * Returns a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     *
     * @return a new {@link JwtParser} instance that can be configured and then used to parse JWT strings.
     * @deprecated use {@link Jwts#parserBuilder()} instead. See {@link JwtParserBuilder} for usage details.
     * <p>Migration to new method structure is minimal, for example:
     * <p>Old code:
     * <pre>{@code
     *     Jwts.parser()
     *         .requireAudience("string")
     *         .parse(jwtString)
     * }</pre>
     * <p>New code:
     * <pre>{@code
     *     Jwts.parserBuilder()
     *         .requireAudience("string")
     *         .build()
     *         .parse(jwtString)
     * }</pre>
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    public static JwtParser parser() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParser");
    }

    /**
     * Returns a new {@link JwtParserBuilder} instance that can be configured to create an immutable/thread-safe {@link JwtParser}.
     *
     * @return a new {@link JwtParser} instance that can be configured create an immutable/thread-safe {@link JwtParser}.
     */
    public static JwtParserBuilder parserBuilder() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwtParserBuilder");
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
}

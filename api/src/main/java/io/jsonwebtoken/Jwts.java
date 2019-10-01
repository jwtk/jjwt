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

import java.util.Map;

/**
 * Factory class useful for creating instances of JWT interfaces.  Using this factory class can be a good
 * alternative to tightly coupling your code to implementation classes.
 *
 * @since 0.1
 */
public final class Jwts {

    private static final Class[] MAP_ARG = new Class[]{Map.class};

    private Jwts() {
    }

    /**
     * Creates a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.  As this
     * is a less common use of JWTs, consider using the {@link #jwsHeader()} factory method instead if you will later
     * digitally sign the JWT.
     *
     * @return a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.
     */
    public static Header header() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultHeader");
    }

    /**
     * Creates a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs, populated
     * with the specified name/value pairs.  As this is a less common use of JWTs, consider using the
     * {@link #jwsHeader(java.util.Map)} factory method instead if you will later digitally sign the JWT.
     *
     * @return a new {@link Header} instance suitable for <em>plaintext</em> (not digitally signed) JWTs.
     */
    public static Header header(Map<String, Object> header) {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultHeader", MAP_ARG, header);
    }

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's).
     *
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's).
     * @see JwtBuilder#setHeader(Header)
     */
    public static JwsHeader jwsHeader() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwsHeader");
    }

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.
     *
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.
     * @see JwtBuilder#setHeader(Header)
     */
    public static JwsHeader jwsHeader(Map<String, Object> header) {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwsHeader", MAP_ARG, header);
    }

    /**
     * Returns a new {@link Claims} instance to be used as a JWT body.
     *
     * @return a new {@link Claims} instance to be used as a JWT body.
     */
    public static Claims claims() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultClaims");
    }

    /**
     * Returns a new {@link Claims} instance populated with the specified name/value pairs.
     *
     * @param claims the name/value pairs to populate the new Claims instance.
     * @return a new {@link Claims} instance populated with the specified name/value pairs.
     */
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
     * Returns a new {@link JwtParserBuilder} instance that can be configured to create an immutable/thread-safe {@link JwtParser).
     *
     * @return a new {@link JwtParser} instance that can be configured create an immutable/thread-safe {@link JwtParser).
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

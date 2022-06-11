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

    @SuppressWarnings("rawtypes")
    private static final Class[] MAP_ARG = new Class[]{Map.class};

    private Jwts() {
    }

    /**
     * Creates a new {@link UnprotectedHeader} instance suitable for unprotected (not digitally signed or encrypted)
     * JWTs.  Because {@code Header} extends {@link Map} and map mutation methods cannot support method chaining,
     * consider using the more flexible {@link #headerBuilder()} method instead, which does support method
     * chaining and other builder conveniences not available on the {@link UnprotectedHeader} interface.
     *
     * @return a new {@link UnprotectedHeader} instance suitable for <em>unprotected</em> (not digitally signed or
     * encrypted) JWTs.
     * @see #headerBuilder()
     */
    public static UnprotectedHeader header() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultUnprotectedHeader");
    }

    /**
     * Creates a new {@link UnprotectedHeader} instance suitable for unprotected (not digitally signed or encrypted)
     * JWTs, populated with the specified name/value pairs. Because {@code Header} extends {@link Map} and map
     * mutation methods cannot support method chaining, consider using the more flexible {@link #headerBuilder()}
     * method instead, which does support method chaining and other builder conveniences not available on the
     * {@link UnprotectedHeader} interface.
     *
     * @param header map of name/value pairs used to create an unprotected (not digitally signed or encrypted) JWT
     *               {@code Header} instance.
     * @return a new {@link UnprotectedHeader} instance suitable for unprotected (not digitally signed or encrypted)
     * JWTs.
     * @see #headerBuilder()
     */
    public static UnprotectedHeader header(Map<String, Object> header) {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultUnprotectedHeader", MAP_ARG, header);
    }

    /**
     * Returns a new {@link DynamicHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     *
     * @return a new {@link DynamicHeaderBuilder} that can build any type of {@link Header} instance depending on
     * which builder properties are set.
     * @since JJWT_RELEASE_VERSION
     */
    public static DynamicHeaderBuilder headerBuilder() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultDynamicHeaderBuilder");
    }

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's). Because {@code Header}
     * extends {@link Map} and map mutation methods cannot support method chaining, consider using the
     * more flexible {@link #headerBuilder()} method instead, which does support method chaining, as well as other
     * convenience builder methods not available via the {@link JwsHeader} interface.
     *
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's).
     * @see #headerBuilder()
     * @see JwtBuilder#setHeader(Header)
     */
    public static JwsHeader jwsHeader() {
        return Classes.newInstance("io.jsonwebtoken.impl.DefaultJwsHeader");
    }

    /**
     * Returns a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.  Because {@code Header} extends {@link Map} and map mutation methods cannot
     * support method chaining, consider using the more flexible {@link #headerBuilder()} method instead,
     * which does support method chaining and other builder conveniences not available on the
     * {@link JwsHeader} interface directly.
     *
     * @param header map of name/value pairs used to create a new {@link JwsHeader} instance.
     * @return a new {@link JwsHeader} instance suitable for digitally signed JWTs (aka 'JWS's), populated with the
     * specified name/value pairs.
     * @see #headerBuilder()
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

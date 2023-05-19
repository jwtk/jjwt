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

import java.util.Map;

/**
 * A JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-5">JOSE header</a>.
 *
 * <p>This is an immutable JSON map with convenient type-safe getters for JWT standard header parameter names.</p>
 *
 * <p>Because this interface extends <code>Map&lt;String, Object&gt;</code>, you can use standard {@code Map}
 * accessor/iterator methods as desired, for example:</p>
 *
 * <blockquote><pre>
 * header.get("someKey");</pre></blockquote>
 *
 * <p>However, because {@code Header} instances are immutable, calling any of the map mutation methods
 * (such as {@code Map.}{@link Map#put(Object, Object) put}, etc) will result in a runtime exception.</p>
 *
 * <p><b>Creation</b></p>
 *
 * <p>It is easiest to create a {@code Header} instance by using a {@link Jwts#header() Jwts.header()} builder.</p>
 *
 * @since 0.1
 */
public interface Header extends HeaderAccessor, Map<String, Object> {

    /**
     * JWT {@code Type} (typ) value: <code>"JWT"</code>
     *
     * @deprecated since JJWT_RELEASE_VERSION - this constant is never used within the JJWT codebase.
     */
    @Deprecated
    String JWT_TYPE = "JWT";

    /**
     * JWT {@code Type} header parameter name: <code>"typ"</code>
     */
    String TYPE = "typ";

    /**
     * JWT {@code Content Type} header parameter name: <code>"cty"</code>
     */
    String CONTENT_TYPE = "cty";

    /**
     * JWT {@code Algorithm} header parameter name: <code>"alg"</code>.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">JWS Algorithm Header</a>
     * @see <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">JWE Algorithm Header</a>
     */
    String ALGORITHM = "alg";

    /**
     * JWT {@code Compression Algorithm} header parameter name: <code>"zip"</code>
     */
    String COMPRESSION_ALGORITHM = "zip";

    /**
     * JJWT legacy/deprecated compression algorithm header parameter name: <code>"calg"</code>
     *
     * @deprecated use {@link #COMPRESSION_ALGORITHM} instead.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    String DEPRECATED_COMPRESSION_ALGORITHM = "calg";
}

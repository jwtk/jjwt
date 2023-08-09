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
 * <p><b>Security</b></p>
 *
 * <p>The {@code Header} interface itself makes no implications of integrity protection via either digital signatures or
 * encryption. Instead, {@link JwsHeader} and {@link JweHeader} represent this information for respective
 * {@link Jws} and {@link Jwe} instances.</p>
 *
 * @see ProtectedHeader
 * @see JwsHeader
 * @see JweHeader
 * @since 0.1
 */
public interface Header extends Map<String, Object> {

    /**
     * JWT {@code Type} (typ) value: <code>"JWT"</code>
     *
     * @deprecated since JJWT_RELEASE_VERSION - this constant is never used within the JJWT codebase.
     */
    @Deprecated
    String JWT_TYPE = "JWT";

    /**
     * JWT {@code Type} header parameter name: <code>"typ"</code>
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getType()}.
     */
    @Deprecated
    String TYPE = "typ";

    /**
     * JWT {@code Content Type} header parameter name: <code>"cty"</code>
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getContentType()}.
     */
    @Deprecated
    String CONTENT_TYPE = "cty";

    /**
     * JWT {@code Algorithm} header parameter name: <code>"alg"</code>.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">JWS Algorithm Header</a>
     * @see <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">JWE Algorithm Header</a>
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getAlgorithm()}.
     */
    @Deprecated
    String ALGORITHM = "alg";

    /**
     * JWT {@code Compression Algorithm} header parameter name: <code>"zip"</code>
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #getCompressionAlgorithm()}
     */
    @Deprecated
    String COMPRESSION_ALGORITHM = "zip";

    /**
     * JJWT legacy/deprecated compression algorithm header parameter name: <code>"calg"</code>
     *
     * @deprecated use {@link #COMPRESSION_ALGORITHM} instead.
     */
    @Deprecated
    String DEPRECATED_COMPRESSION_ALGORITHM = "calg";

    /**
     * Returns the <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1">
     * <code>typ</code> (Type)</a> header value or {@code null} if not present.
     *
     * @return the {@code typ} header value or {@code null} if not present.
     */
    String getType();

    /**
     * Returns the <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10">
     * <code>cty</code> (Content Type)</a> header value or {@code null} if not present.
     *
     * <p>The <code>cty</code> (Content Type) Header Parameter is used by applications to declare the
     * <a href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA MediaType</a> of the content
     * (the payload).  This is intended for use by the application when more than
     * one kind of object could be present in the Payload; the application can use this value to disambiguate among
     * the different kinds of objects that might be present.  It will typically not be used by applications when
     * the kind of object is already known.  This parameter is ignored by JWT implementations (like JJWT); any
     * processing of this parameter is performed by the JWS application.  Use of this Header Parameter is OPTIONAL.</p>
     *
     * <p>To keep messages compact in common situations, it is RECOMMENDED that producers omit an
     * <b><code>application/</code></b> prefix of a media type value in a {@code cty} Header Parameter when
     * no other '<b>/</b>' appears in the media type value.  A recipient using the media type value <em>MUST</em>
     * treat it as if <b><code>application/</code></b> were prepended to any {@code cty} value not containing a
     * '<b>/</b>'. For instance, a {@code cty} value of <b><code>example</code></b> <em>SHOULD</em> be used to
     * represent the <b><code>application/example</code></b> media type, whereas the media type
     * <b><code>application/example;part=&quot;1/2&quot;</code></b> cannot be shortened to
     * <b><code>example;part=&quot;1/2&quot;</code></b>.</p>
     *
     * @return the {@code typ} header parameter value or {@code null} if not present.
     */
    String getContentType();

    /**
     * Returns the JWT {@code alg} (Algorithm) header value or {@code null} if not present.
     *
     * <ul>
     *     <li>If the JWT is a Signed JWT (a JWS), the <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">
     *      <code>alg</code></a> (Algorithm) header parameter identifies the cryptographic algorithm used to secure the
     *      JWS.  Consider using {@link Jwts.SIG}.{@link io.jsonwebtoken.lang.Registry#get(Object) get(id)}
     *      to convert this string value to a type-safe {@code SecureDigestAlgorithm} instance.</li>
     *      <li>If the JWT is an Encrypted JWT (a JWE), the
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1"><code>alg</code></a> (Algorithm) header parameter
     * identifies the cryptographic key management algorithm used to encrypt or determine the value of the Content
     * Encryption Key (CEK).  The encrypted content is not usable if the <code>alg</code> value does not represent a
     * supported algorithm, or if the recipient does not have a key that can be used with that algorithm.  Consider
     * using {@link Jwts.KEY}.{@link io.jsonwebtoken.lang.Registry#get(Object) get(id)} to convert this string value
     * to a type-safe {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm} instance.</li>
     * </ul>
     *
     * @return the {@code alg} header value or {@code null} if not present.  This will always be
     * {@code non-null} on validly constructed JWT instances, but could be {@code null} during construction.
     * @since JJWT_RELEASE_VERSION
     */
    String getAlgorithm();

    /**
     * Returns the JWT  <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a>
     * (Compression Algorithm) header parameter value or {@code null} if not present.
     *
     * <p><b>Compatibility Note</b></p>
     *
     * <p>While the JWT family of specifications only defines the <code>zip</code> header in the JWE
     * (JSON Web Encryption) specification, JJWT will also support compression for JWS as well if you choose to use it.
     * However, be aware that <b>if you use compression when creating a JWS token, other libraries may not be able to
     * parse the JWS</b>. However, compression when creating JWE tokens should be universally accepted for any library
     * that supports JWE.</p>
     *
     * @return the {@code zip} header parameter value or {@code null} if not present.
     * @since 0.6.0
     */
    String getCompressionAlgorithm();
}

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
 * A JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5">JOSE header</a>.
 *
 * <p>This is ultimately a JSON map and any values can be added to it, but JWT JOSE standard names are provided as
 * type-safe getters and setters for convenience.</p>
 *
 * <p>Because this interface extends {@code Map&lt;String, Object&gt;}, if you would like to add your own properties,
 * you simply use map methods, for example:</p>
 *
 * <pre>
 * header.{@link Map#put(Object, Object) put}("headerParamName", "headerParamValue");
 * </pre>
 *
 * <h3>Creation</h3>
 *
 * <p>It is easiest to create a {@code Header} instance by calling one of the
 * {@link Jwts#header() Jwts.header()} factory methods.</p>
 *
 * @since 0.1
 */
public interface Header<T extends Header<T>> extends Map<String,Object> {

    /** JWT {@code Type} (typ) value: <code>"JWT"</code> */
    public static final String JWT_TYPE = "JWT";

    /** JWT {@code Type} header parameter name: <code>"typ"</code> */
    public static final String TYPE = "typ";

    /** JWT {@code Content Type} header parameter name: <code>"cty"</code> */
    public static final String CONTENT_TYPE = "cty";

    /**
     * JWT {@code Algorithm} header parameter name: <code>"alg"</code>.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">JWS Algorithm Header</a>
     * @see <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">JWE Algorithm Header</a>
     */
    public static final String ALGORITHM = "alg";

    /** JWT {@code Compression Algorithm} header parameter name: <code>"zip"</code> */
    public static final String COMPRESSION_ALGORITHM = "zip";

    /** JJWT legacy/deprecated compression algorithm header parameter name: <code>"calg"</code>
     * @deprecated use {@link #COMPRESSION_ALGORITHM} instead. */
    @Deprecated
    public static final String DEPRECATED_COMPRESSION_ALGORITHM = "calg";

    /**
     * Returns the <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.1">
     * <code>typ</code></a> (type) header value or {@code null} if not present.
     *
     * @return the {@code typ} header value or {@code null} if not present.
     */
    String getType();

    /**
     * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.1">
     * <code>typ</code></a> (Type) header value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param typ the JWT JOSE {@code typ} header value or {@code null} to remove the property from the JSON map.
     * @return the {@code Header} instance for method chaining.
     */
    T setType(String typ);

    /**
     * Returns the <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.2">
     * <code>cty</code></a> (Content Type) header value or {@code null} if not present.
     *
     * <p>In the normal case where nested signing or encryption operations are not employed (i.e. a compact
     * serialization JWT), the use of this header parameter is NOT RECOMMENDED.  In the case that nested
     * signing or encryption is employed, this Header Parameter MUST be present; in this case, the value MUST be
     * {@code JWT}, to indicate that a Nested JWT is carried in this JWT.  While media type names are not
     * case-sensitive, it is RECOMMENDED that {@code JWT} always be spelled using uppercase characters for
     * compatibility with legacy implementations.  See
     * <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#appendix-A.2">JWT Appendix A.2</a> for
     * an example of a Nested JWT.</p>
     *
     * @return the {@code typ} header parameter value or {@code null} if not present.
     */
    String getContentType();

    /**
     * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.2">
     * <code>cty</code></a> (Content Type) header parameter value.  A {@code null} value will remove the property from
     * the JSON map.
     *
     * <p>In the normal case where nested signing or encryption operations are not employed (i.e. a compact
     * serialization JWT), the use of this header parameter is NOT RECOMMENDED.  In the case that nested
     * signing or encryption is employed, this Header Parameter MUST be present; in this case, the value MUST be
     * {@code JWT}, to indicate that a Nested JWT is carried in this JWT.  While media type names are not
     * case-sensitive, it is RECOMMENDED that {@code JWT} always be spelled using uppercase characters for
     * compatibility with legacy implementations.  See
     * <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#appendix-A.2">JWT Appendix A.2</a> for
     * an example of a Nested JWT.</p>
     *
     * @param cty the JWT JOSE {@code cty} header value or {@code null} to remove the property from the JSON map.
     */
    T setContentType(String cty);

    /**
     * Returns the JWT {@code alg} (Algorithm) header value or {@code null} if not present.
     *
     * <ul>
     *     <li>If the JWT is a Signed JWT (a JWS), the <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">
     *      <code>alg</code></a> (Algorithm) header parameter identifies the cryptographic algorithm used to secure the
     *      JWS.  Consider using
     *      {@link io.jsonwebtoken.security.SignatureAlgorithms#forName(String) SignatureAlgorithms.forName} to
     *      convert this string value to a type-safe enum instance.</li>
     *      <li>If the JWT is an Encrypted JWT (a JWE), the
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1"><code>alg</code></a> (Algorithm) header parameter
     * identifies the cryptographic key management algorithm used to encrypt or determine the value of the Content
     * Encryption Key (CEK).  The encrypted content is not usable if the <code>alg</code> value does not represent a
     * supported algorithm, or if the recipient does not have a key that can be used with that algorithm</li>
     * </ul>
     *
     * @return the {@code alg} header value or {@code null} if not present.  This will always be
     * {@code non-null} on validly constructed JWT instances, but could be {@code null} during construction.
     * @since JJWT_RELEASE_VERSION
     */
    String getAlgorithm();

    /**
     * Sets the JWT <code>alg</code></a> (Algorithm) header value.  A {@code null} value will remove the property
     * from the JSON map.
     * <ul>
     *     <li>If the JWT is a Signed JWT (a JWS), the <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">
     *      <code>alg</code></a> (Algorithm) header parameter identifies the cryptographic algorithm used to secure the
     *      JWS.  Consider using
     *      {@link io.jsonwebtoken.security.SignatureAlgorithms#forName(String) SignatureAlgorithms.forName} to
     *      convert this string value to a type-safe enum instance.</li>
     *      <li>If the JWT is an Encrypted JWT (a JWE), the
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1"><code>alg</code></a> (Algorithm) header parameter
     * identifies the cryptographic key management algorithm used to encrypt or determine the value of the Content
     * Encryption Key (CEK).  The encrypted content is not usable if the <code>alg</code> value does not represent a
     * supported algorithm, or if the recipient does not have a key that can be used with that algorithm</li>
     * </ul>
     *
     * @param alg the {@code alg} header value
     * @return this header for method chaining
     * @since JJWT_RELEASE_VERSION
     */
    T setAlgorithm(String alg);

    /**
     * Returns the JWT  <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a>
     * (Compression Algorithm) header parameter value or {@code null} if not present.
     *
     * <h3>Compatiblity Note</h3>
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

    /**
     * Sets the JWT  <a href="https://tools.ietf.org/html/rfc7516#section-4.1.3"><code>zip</code></a>
     * (Compression Algorithm) header parameter value. A {@code null} value will remove
     * the property from the JSON map.
     * <p>The compression algorithm is NOT part of the <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25">JWT specification</a>
     * and must be used carefully since, is not expected that other libraries (including previous versions of this one)
     * be able to deserialize a compressed JWT body correctly. </p>
     *
     * <h3>Compatibility Note</h3>
     *
     * <p>While the JWT family of specifications only defines the <code>zip</code> header in the JWE
     * (JSON Web Encryption) specification, JJWT will also support compression for JWS as well if you choose to use it.
     * However, be aware that <b>if you use compression when creating a JWS token, other libraries may not be able to
     * parse the JWS</b>. However, Compression when creating JWE tokens should be universally accepted for any library
     * that supports JWE.</p>
     *
     * @param zip the JWT compression algorithm {@code zip} value or {@code null} to remove the property from the
     *  JSON map.
     * @since 0.6.0
     */
    T setCompressionAlgorithm(String zip);

}

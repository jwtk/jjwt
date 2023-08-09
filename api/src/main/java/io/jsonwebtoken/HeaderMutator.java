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
package io.jsonwebtoken;

import io.jsonwebtoken.lang.MapMutator;

/**
 * Mutation (modifications) to a {@link Header Header} instance.
 *
 * @param <T> the mutator subtype, for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface HeaderMutator<T extends HeaderMutator<T>> extends MapMutator<String, Object, T> {

    //IMPLEMENTOR NOTE: if this `algorithm` method ever needs to be exposed in the public API, it might be better to
    //                  have it in the Jwts.HeaderBuilder interface and NOT this one: in the context of
    //                  JwtBuilder.Header, there is never a reason for an application developer to call algorithm(id)
    //                  directly because the KeyAlgorithm or SecureDigestAlgorithm instance must always be provided
    //                  via the signWith or encryptWith methods.  The JwtBuilder will always set the algorithm
    //                  header based on these two instances, so there is no need for an app dev to do so.
    /*
     * Sets the JWT {@code alg} (Algorithm) header value.  A {@code null} value will remove the property
     * from the JSON map.
     * <ul>
     *     <li>If the JWT is a Signed JWT (a JWS), the
     *     <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1">{@code alg}</a> (Algorithm) header
     *     parameter identifies the cryptographic algorithm used to secure the JWS.</li>
     *      <li>If the JWT is an Encrypted JWT (a JWE), the
     * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1"><code>alg</code></a> (Algorithm) header parameter
     * identifies the cryptographic key management algorithm used to encrypt or determine the value of the Content
     * Encryption Key (CEK).  The encrypted content is not usable if the <code>alg</code> value does not represent a
     * supported algorithm, or if the recipient does not have a key that can be used with that algorithm.</li>
     * </ul>
     *
     * @param alg the {@code alg} header value
     * @return this header for method chaining
     * @since JJWT_RELEASE_VERSION
     *
    T algorithm(String alg);
    */

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1">
     * <code>typ</code> (Type)</a> header value.  A {@code null} value will remove the property from the JSON map.
     *
     * @param typ the JWT JOSE {@code typ} header value or {@code null} to remove the property from the JSON map.
     * @return the instance for method chaining.
     */
    T type(String typ);

    /**
     * Sets the compact <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10">
     * <code>cty</code> (Content Type)</a> header parameter value, used by applications to declare the
     * <a href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA MediaType</a> of the JWT
     * payload.  A {@code null} value will remove the property from the JSON map.
     *
     * <p><b>Compact Media Type Identifier</b></p>
     *
     * <p>This method will automatically remove any <code><b>application/</b></code> prefix from the
     * {@code cty} string if possible according to the rules defined in the last paragraph of
     * <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10">RFC 7517, Section 4.1.10</a>:</p>
     * <blockquote><pre>
     *     To keep messages compact in common situations, it is RECOMMENDED that
     *     producers omit an "application/" prefix of a media type value in a
     *     "cty" Header Parameter when no other '/' appears in the media type
     *     value.  A recipient using the media type value MUST treat it as if
     *     "application/" were prepended to any "cty" value not containing a
     *     '/'.  For instance, a "cty" value of "example" SHOULD be used to
     *     represent the "application/example" media type, whereas the media
     *     type "application/example;part="1/2"" cannot be shortened to
     *     "example;part="1/2"".</pre></blockquote>
     *
     * <p>JJWT performs the reverse during JWT parsing: {@link Header#getContentType()} will automatically prepend the
     * {@code application/} prefix if the parsed {@code cty} value does not contain a '<code>/</code>' character (as
     * mandated by the RFC language above). This ensures application developers can use and read standard IANA Media
     * Type identifiers without needing JWT-specific prefix conditional logic in application code.
     * </p>
     *
     * @param cty the JWT {@code cty} header value or {@code null} to remove the property from the JSON map.
     * @return the instance for method chaining.
     */
    T contentType(String cty);

    /**
     * Deprecated since of JJWT_RELEASE_VERSION, delegates to {@link #type(String)}.
     *
     * @param typ the JWT JOSE {@code typ} header value or {@code null} to remove the property from the JSON map.
     * @return the instance for method chaining.
     * @see #type(String)
     * @deprecated since JJWT_RELEASE_VERSION in favor of the more modern builder-style {@link #type(String)} method.
     * This method will be removed before the 1.0 release.
     */
    @Deprecated
    T setType(String typ);

    /**
     * Deprecated as of JJWT_RELEASE_VERSION, delegates to {@link #contentType(String)}.
     *
     * @param cty the JWT JOSE {@code cty} header value or {@code null} to remove the property from the JSON map.
     * @return the instance for method chaining.
     * @see #contentType(String)
     * @deprecated since JJWT_RELEASE_VERSION in favor of the more modern builder-style {@link #contentType(String)}.
     */
    @Deprecated
    T setContentType(String cty);

    /**
     * Deprecated as of JJWT_RELEASE_VERSION, there is no need to set this any longer as the {@code JwtBuilder} will
     * always set the {@code zip} header as necessary.
     *
     * @param zip the JWT compression algorithm {@code zip} value or {@code null} to remove the property from the JSON map.
     * @return the instance for method chaining.
     * @since 0.6.0
     * @deprecated since JJWT_RELEASE_VERSION and will be removed before the 1.0 release.
     */
    @Deprecated
    T setCompressionAlgorithm(String zip);
}

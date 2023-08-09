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
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10">
     * <code>cty</code> (Content Type)</a> header parameter value.  A {@code null} value will remove the property from
     * the JSON map.
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
     * @param cty the JWT JOSE {@code cty} header value or {@code null} to remove the property from the JSON map.
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

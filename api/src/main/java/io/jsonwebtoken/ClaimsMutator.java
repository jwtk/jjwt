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

import io.jsonwebtoken.lang.NestedCollection;

import java.util.Collection;
import java.util.Date;

/**
 * Mutation (modifications) to a {@link io.jsonwebtoken.Claims Claims} instance.
 *
 * @param <T> the type of mutator
 * @see io.jsonwebtoken.JwtBuilder
 * @see io.jsonwebtoken.Claims
 * @since 0.2
 */
public interface ClaimsMutator<T extends ClaimsMutator<T>> {

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1">
     * <code>iss</code></a> (issuer) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * @param iss the JWT {@code iss} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #issuer(String)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setIssuer(String iss);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1">
     * <code>iss</code></a> (issuer) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * @param iss the JWT {@code iss} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T issuer(String iss);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2">
     * <code>sub</code></a> (subject) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * @param sub the JWT {@code sub} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #subject(String)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setSubject(String sub);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2">
     * <code>sub</code></a> (subject) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * @param sub the JWT {@code sub} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T subject(String sub);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3"><code>aud</code> (audience)
     * claim</a> as <em>a single String, <b>NOT</b> a String array</em>.  This method exists only for producing
     * JWTs sent to legacy recipients that are unable to interpret the {@code aud} value as a JSON String Array; it is
     * strongly recommended to avoid calling this method whenever possible and favor the
     * {@link #audience()}.{@link AudienceCollection#add(Object) add(String)} and
     * {@link AudienceCollection#add(Collection) add(Collection)} methods instead, as they ensure a single
     * deterministic data type for recipients.
     *
     * @param aud the JWT {@code aud} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of {@link #audience()}. This method will be removed before
     * the JJWT 1.0 release.
     */
    @Deprecated
    T setAudience(String aud);

    /**
     * Configures the JWT
     * <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3"><code>aud</code></a> (audience) Claim
     * set, quietly ignoring any null, empty, whitespace-only, or existing value already in the set.
     *
     * <p>When finished, the {@code audience} collection's {@link AudienceCollection#and() and()} method may be used
     * to continue configuration. For example:</p>
     * <blockquote><pre>
     *  Jwts.builder() // or Jwts.claims()
     *
     *     .audience().add("anAudience")<b>.and() // return parent</b>
     *
     *  .subject("Joe") // resume configuration...
     *  // etc...
     * </pre></blockquote>
     *
     * @return the {@link AudienceCollection AudienceCollection} to use for {@code aud} configuration.
     * @see AudienceCollection AudienceCollection
     * @see AudienceCollection#single(String) AudienceCollection.single(String)
     * @since 0.12.0
     */
    AudienceCollection<T> audience();

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4">
     * <code>exp</code></a> (expiration) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>A JWT obtained after this timestamp should not be used.</p>
     *
     * @param exp the JWT {@code exp} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #expiration(Date)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setExpiration(Date exp);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4">
     * <code>exp</code></a> (expiration) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>A JWT obtained after this timestamp should not be used.</p>
     *
     * @param exp the JWT {@code exp} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T expiration(Date exp);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5">
     * <code>nbf</code></a> (not before) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>A JWT obtained before this timestamp should not be used.</p>
     *
     * @param nbf the JWT {@code nbf} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #notBefore(Date)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setNotBefore(Date nbf);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5">
     * <code>nbf</code></a> (not before) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>A JWT obtained before this timestamp should not be used.</p>
     *
     * @param nbf the JWT {@code nbf} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T notBefore(Date nbf);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6">
     * <code>iat</code></a> (issued at) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>The value is the timestamp when the JWT was created.</p>
     *
     * @param iat the JWT {@code iat} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #issuedAt(Date)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setIssuedAt(Date iat);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6">
     * <code>iat</code></a> (issued at) timestamp claim.  A {@code null} value will remove the property from the
     * JSON Claims map.
     *
     * <p>The value is the timestamp when the JWT was created.</p>
     *
     * @param iat the JWT {@code iat} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T issuedAt(Date iat);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7">
     * <code>jti</code></a> (JWT ID) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * <p>This value is a CaSe-SenSiTiVe unique identifier for the JWT. If specified, this value MUST be assigned in a
     * manner that ensures that there is a negligible probability that the same value will be accidentally
     * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
     *
     * @param jti the JWT {@code jti} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @deprecated since 0.12.0 in favor of the shorter and more modern builder-style named
     * {@link #id(String)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    T setId(String jti);

    /**
     * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7">
     * <code>jti</code></a> (JWT ID) claim.  A {@code null} value will remove the property from the JSON Claims map.
     *
     * <p>This value is a CaSe-SenSiTiVe unique identifier for the JWT. If specified, this value MUST be assigned in a
     * manner that ensures that there is a negligible probability that the same value will be accidentally
     * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
     *
     * @param jti the JWT {@code jti} value or {@code null} to remove the property from the JSON map.
     * @return the {@code Claims} instance for method chaining.
     * @since 0.12.0
     */
    T id(String jti);

    /**
     * A {@code NestedCollection} for setting {@link #audience()} values that also allows overriding the collection
     * to be a {@link #single(String) single string value} for legacy JWT recipients if necessary.
     *
     * <p>Because this interface extends {@link NestedCollection}, the {@link #and()} method may be used to continue
     * parent configuration. For example:</p>
     * <blockquote><pre>
     *  Jwts.builder() // or Jwts.claims()
     *
     *     .audience().add("anAudience")<b>.and() // return parent</b>
     *
     *  .subject("Joe") // resume parent configuration...
     *  // etc...</pre></blockquote>
     *
     * @param <P> the type of ClaimsMutator to return for method chaining.
     * @see #single(String)
     * @since 0.12.0
     */
    interface AudienceCollection<P> extends NestedCollection<String, P> {

        /**
         * Sets the JWT <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3"><code>aud</code> (audience)
         * Claim</a> as <em>a single String, <b>NOT</b> a String array</em>.  This method exists only for producing
         * JWTs sent to legacy recipients that are unable to interpret the {@code aud} value as a JSON String Array;
         * it is strongly recommended to avoid calling this method whenever possible and favor the
         * {@link #add(Object) add(String)} or {@link #add(Collection)} methods instead, as they ensure a single
         * deterministic data type for recipients.
         *
         * @param aud the value to use as the {@code aud} Claim single-String value (and not an array of Strings), or
         *            {@code null}, empty or whitespace to remove the property from the JSON map.
         * @return the instance for method chaining
         * @since 0.12.0
         * @deprecated This is technically not deprecated because the JWT RFC mandates support for single string values,
         * but it is marked as deprecated to discourage its use when possible.
         */
        // DO NOT REMOVE EVER. This is a required RFC feature, but marked as deprecated to discourage its use
        @Deprecated
        P single(String aud);
    }
}

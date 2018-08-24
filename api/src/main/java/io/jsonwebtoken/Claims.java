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

import java.util.Date;
import java.util.Map;

/**
 * A JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4">Claims set</a>.
 *
 * <p>This is ultimately a JSON map and any values can be added to it, but JWT standard names are provided as
 * type-safe getters and setters for convenience.</p>
 *
 * <p>Because this interface extends {@code Map&lt;String, Object&gt;}, if you would like to add your own properties,
 * you simply use map methods, for example:</p>
 *
 * <pre>
 * claims.{@link Map#put(Object, Object) put}("someKey", "someValue");
 * </pre>
 *
 * <h3>Creation</h3>
 *
 * <p>It is easiest to create a {@code Claims} instance by calling one of the
 * {@link Jwts#claims() JWTs.claims()} factory methods.</p>
 *
 * @since 0.1
 */
public interface Claims extends Map<String, Object>, ClaimsMutator<Claims> {

    /** JWT {@code Issuer} claims parameter name: <code>"iss"</code> */
    public static final String ISSUER = "iss";

    /** JWT {@code Subject} claims parameter name: <code>"sub"</code> */
    public static final String SUBJECT = "sub";

    /** JWT {@code Audience} claims parameter name: <code>"aud"</code> */
    public static final String AUDIENCE = "aud";

    /** JWT {@code Expiration} claims parameter name: <code>"exp"</code> */
    public static final String EXPIRATION = "exp";

    /** JWT {@code Not Before} claims parameter name: <code>"nbf"</code> */
    public static final String NOT_BEFORE = "nbf";

    /** JWT {@code Issued At} claims parameter name: <code>"iat"</code> */
    public static final String ISSUED_AT = "iat";

    /** JWT {@code JWT ID} claims parameter name: <code>"jti"</code> */
    public static final String ID = "jti";

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
     * <code>iss</code></a> (issuer) value or {@code null} if not present.
     *
     * @return the JWT {@code iss} value or {@code null} if not present.
     */
    String getIssuer();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setIssuer(String iss);

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
     * <code>sub</code></a> (subject) value or {@code null} if not present.
     *
     * @return the JWT {@code sub} value or {@code null} if not present.
     */
    String getSubject();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setSubject(String sub);

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
     * <code>aud</code></a> (audience) value or {@code null} if not present.
     *
     * @return the JWT {@code aud} value or {@code null} if not present.
     */
    String getAudience();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setAudience(String aud);

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
     * <code>exp</code></a> (expiration) timestamp or {@code null} if not present.
     *
     * <p>A JWT obtained after this timestamp should not be used.</p>
     *
     * @return the JWT {@code exp} value or {@code null} if not present.
     */
    Date getExpiration();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setExpiration(Date exp);

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
     * <code>nbf</code></a> (not before) timestamp or {@code null} if not present.
     *
     * <p>A JWT obtained before this timestamp should not be used.</p>
     *
     * @return the JWT {@code nbf} value or {@code null} if not present.
     */
    Date getNotBefore();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setNotBefore(Date nbf);

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
     * <code>iat</code></a> (issued at) timestamp or {@code null} if not present.
     *
     * <p>If present, this value is the timestamp when the JWT was created.</p>
     *
     * @return the JWT {@code nbf} value or {@code null} if not present.
     */
    Date getIssuedAt();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setIssuedAt(Date iat);

    /**
     * Returns the JWTs <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
     * <code>jti</code></a> (JWT ID) value or {@code null} if not present.
     *
     * <p>This value is a CaSe-SenSiTiVe unique identifier for the JWT. If available, this value is expected to be
     * assigned in a manner that ensures that there is a negligible probability that the same value will be
     * accidentally
     * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
     *
     * @return the JWT {@code jti} value or {@code null} if not present.
     */
    String getId();

    /**
     * {@inheritDoc}
     */
    @Override //only for better/targeted JavaDoc
    Claims setId(String jti);

    <T> T get(String claimName, Class<T> requiredType);

    String getAsString(String claimName);

    Integer getAsInt(String claimName);

    Long getAsLong(String claimName);

    Short getAsShort(String claimName);

    Byte getAsByte(String claimName);

    Date getAsDate(String claimName);

    Boolean getAsBoolean(String claimName);

    Map<String, ?> getAsMap(String claimName);
}

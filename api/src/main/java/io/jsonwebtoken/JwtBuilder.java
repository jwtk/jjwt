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

import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.MapMutator;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;
import io.jsonwebtoken.security.X509Builder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Date;
import java.util.Map;

/**
 * A builder for constructing Unprotected JWTs, Signed JWTs (aka 'JWS's) and Encrypted JWTs (aka 'JWE's).
 *
 * @since 0.1
 */
public interface JwtBuilder extends ClaimsMutator<JwtBuilder> {

    /**
     * Sets the JCA Provider to use during cryptographic signing or encryption operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic signing or encryption operations, or {@code null} if the
     *                 JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder provider(Provider provider);

    /**
     * Sets the {@link SecureRandom} to use during cryptographic signing or encryption operations, or {@code null} if
     * a default {@link SecureRandom} should be used.
     *
     * @param secureRandom the {@link SecureRandom} to use during cryptographic signing or encryption operations, or
     *                     {@code null} if a default {@link SecureRandom} should be used.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder random(SecureRandom secureRandom);

    /**
     * Returns the {@code Header} to use to modify the constructed JWT's header name/value pairs as desired.
     * When finished, callers may return to JWT construction via the {@link BuilderHeader#and() and()} method.
     * For example:
     *
     * <blockquote><pre>
     * String jwt = Jwts.builder()
     *
     *     <b>.header()
     *         .keyId("keyId")
     *         .add("aName", aValue)
     *         .add(myHeaderMap)
     *         // ... etc ...
     *         .{@link BuilderHeader#and() and()}</b> //return back to the JwtBuilder
     *
     *     .subject("Joe") // resume JwtBuilder calls
     *     // ... etc ...
     *     .compact();</pre></blockquote>
     *
     * @return the {@link BuilderHeader} to use for header construction.
     * @since JJWT_RELEASE_VERSION
     */
    BuilderHeader header();

    /**
     * Per standard Java idiom 'setter' conventions, this method sets (and fully replaces) any existing header with the
     * specified name/value pairs.  This is a wrapper method for:
     *
     * <blockquote><pre>
     * {@link #header()}.{@link MapMutator#empty() empty()}.{@link MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</pre></blockquote>
     *
     * <p>If you do not want to replace the existing header and only want to append to it,
     * call <code>{@link #header()}.{@link io.jsonwebtoken.lang.MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</code> instead.</p>
     *
     * @param map the name/value pairs to set as (and potentially replace) the constructed JWT header.
     * @return the builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of
     * <code>{@link #header()}.{@link MapMutator#empty() empty()}.{@link MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</code>
     * (to replace all header parameters) or
     * <code>{@link #header()}.{@link MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</code>
     * to only append the {@code map} entries.  This method will be removed before the 1.0 release.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder setHeader(Map<String, ?> map);

    /**
     * Adds the specified name/value pairs to the header.  Any parameter with an empty or null value will remove the
     * entry from the header. This is a wrapper method for:
     * <blockquote><pre>
     * {@link #header()}.{@link MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</pre></blockquote>
     *
     * @param params the header name/value pairs to append to the header.
     * @return the builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of
     * <code>{@link #header()}.{@link MapMutator#add(Map) add(map)}.{@link BuilderHeader#and() and()}</code>.
     * This method will be removed before the 1.0 release.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder setHeaderParams(Map<String, ?> params);

    /**
     * Adds the specified name/value pair to the header. If the value is {@code null} or empty, the parameter will
     * be removed from the header entirely. This is a wrapper method for:
     * <blockquote><pre>
     * {@link #header()}.{@link MapMutator#add(Object, Object) add(name, value)}.{@link BuilderHeader#and() and()}</pre></blockquote>
     *
     * @param name  the header parameter name
     * @param value the header parameter value
     * @return the builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of <code>
     * {@link #header()}.{@link MapMutator#add(Object, Object) add(name, value)}.{@link BuilderHeader#and() and()}</code>.
     * This method will be removed before the 1.0 release.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder setHeaderParam(String name, Object value);

    /**
     * Sets the JWT payload to the string's UTF-8-encoded bytes.  It is strongly recommended to also set the
     * {@link BuilderHeader#contentType(String) contentType} header value so the JWT recipient may inspect that value to
     * determine how to convert the byte array to the final data type as desired. In this case, consider using
     * {@link #content(byte[], String)} instead.
     *
     * <p>This is a wrapper method for:</p>
     * <blockquote><pre>s
     * {@link #content(byte[]) setPayload}(payload.getBytes(StandardCharsets.UTF_8));</pre></blockquote>
     *
     * <p>If you want the JWT payload to be JSON, use the {@link #claims()} method instead.</p>
     *
     * <p>This method is mutually exclusive of the {@link #claims()} and {@link #claim(String, Object)}
     * methods.  Either {@code claims} or {@code content}/{@code payload} method variants may be used, but not both.</p>
     *
     * @param payload the string used to set UTF-8-encoded bytes as the JWT payload.
     * @return the builder for method chaining.
     * @see #content(byte[])
     * @see #content(byte[], String)
     * @deprecated since JJWT_RELEASE VERSION in favor of {@link #content(byte[])} or {@link #content(byte[], String)}
     * because both Claims and Content are technically 'payloads', so this method name is misleading.  This method will
     * be removed before the 1.0 release.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder setPayload(String payload);

    /**
     * Sets the JWT payload to be the specified content byte array.
     *
     * <p><b>Content Type Recommendation</b></p>
     *
     * <p>Unless you are confident that the JWT recipient will <em>always</em> know how to use
     * the given byte array without additional metadata, it is strongly recommended to use the
     * {@link #content(byte[], String)} method instead of this one.  That method ensures that a JWT recipient
     * can inspect the {@code cty} header to know how to handle the byte array without ambiguity.</p>
     *
     * <p><b>Mutually Exclusive Claims and Content</b></p>
     *
     * <p>This method is mutually exclusive of the {@link #claim(String, Object)} and {@link #claims()}
     * methods. Either {@code claims} or {@code content} method variants may be used, but not both. If you want the
     * JWT payload to be JSON claims, use the {@link #claim(String, Object)} or {@link #claims()} methods instead.</p>
     *
     * @param content the content byte array to use as the JWT payload
     * @return the builder for method chaining.
     * @see #content(byte[], String)
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder content(byte[] content);

    /**
     * Sets the JWT payload to be the specified content byte array and also sets the
     * {@link BuilderHeader#contentType(String) contentType} header value to a compact {@code cty} IANA Media Type
     * identifier to indicate the data format of the byte array. The JWT recipient can inspect the
     * {@code cty} value to determine how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method semantically equivalent to:</p>
     * <blockquote><pre>
     *     {@link #header()}.{@link HeaderMutator#contentType(String) contentType(cty)}.{@link BuilderHeader#and() and()}
     *     {@link #content(byte[]) content(content)}</pre></blockquote>
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
     * <p><b>Mutually Exclusive Claims and Content</b></p>
     *
     * <p>This method is mutually exclusive of the {@link #claim(String, Object)} and {@link #claims()}
     * methods. Either {@code claims} or {@code content} method variants may be used, but not both. If you want the
     * JWT payload to be JSON claims, use the {@link #claim(String, Object)} or {@link #claims()} methods instead.</p>
     *
     * @param content the content byte array that will be the JWT payload.  Cannot be null or empty.
     * @param cty     the content type (media type) identifier attributed to the byte array. Cannot be null or empty.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if either {@code payload} or {@code cty} are null or empty.
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder content(byte[] content, String cty) throws IllegalArgumentException;

    /**
     * Returns the JWT {@code Claims} payload to modify as desired. When finished, callers may
     * return to {@code JwtBuilder} configuration via the {@link BuilderClaims#and() and()} method.
     * For example:
     *
     * <blockquote><pre>
     * String jwt = Jwts.builder()
     *
     *     <b>.claims()
     *         .subject("Joe")
     *         .audience("you")
     *         .issuer("me")
     *         .add("customClaim", customValue)
     *         .add(myClaimsMap)
     *         // ... etc ...
     *         .{@link BuilderClaims#and() and()}</b> //return back to the JwtBuilder
     *
     *     .signWith(key) // resume JwtBuilder calls
     *     // ... etc ...
     *     .compact();</pre></blockquote>
     *
     * @return the {@link BuilderClaims} to use for Claims construction.
     * @since JJWT_RELEASE_VERSION
     */
    BuilderClaims claims();

    /**
     * Sets (and replaces) the JWT Claims payload with the specified name/value pairs. If you do not want the JWT
     * payload to be JSON claims and instead want it to be a byte array for any content, use the
     * {@link #content(byte[])} or {@link #content(byte[], String)} methods instead.
     *
     * <p>The content and claims properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param claims the JWT Claims to be set as the JWT payload.
     * @return the builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of the more modern builder-style {@link #claims()} method.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder setClaims(Map<String, ?> claims);

    /**
     * Adds/appends all given name/value pairs to the JSON Claims in the payload.
     * <p>
     * This is a convenience wrapper for:
     *
     * <blockquote><pre>
     * {@link #claims()}.{@link MapMutator#add(Map) add(claims)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * <p>The content and claims properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param claims the JWT Claims to be added to the JWT payload.
     * @return the builder for method chaining.
     * @since 0.8
     * @deprecated since JJWT_RELEASE_VERSION in favor of
     * <code>{@link #claims()}.{@link BuilderClaims#add(Map) add(Map)}.{@link BuilderClaims#and() and()}</code>.
     * This method will be removed before the 1.0 release.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtBuilder addClaims(Map<String, ?> claims);

    /**
     * Sets a JWT claim, overwriting any existing claim with the same name. A {@code null} or empty
     * value will remove the claim entirely. This is a convenience wrapper for:
     * <blockquote><pre>
     * {@link #claims()}.{@link MapMutator#add(Object, Object) add(name, value)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param name  the JWT Claims property name
     * @param value the value to set for the specified Claims property name
     * @return the builder instance for method chaining.
     * @since 0.2
     */
    JwtBuilder claim(String name, Object value);

    /**
     * Adds all given name/value pairs to the JSON Claims in the payload, overwriting any existing claims
     * with the same names.  If any name has a {@code null} or empty value, that claim will be removed from the
     * Claims.  This is a convenience wrapper for:
     * <blockquote><pre>
     * {@link #claims()}.{@link MapMutator#add(Map) add(claims)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * <p>The content and claims properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param claims the JWT Claims to be added to the JWT payload.
     * @return the builder instance for method chaining
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder claims(Map<String, ?> claims);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1">
     * <code>iss</code></a> (issuer) value.  A {@code null} value will remove the property from the Claims.
     * This is a convenience wrapper for:
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#issuer(String) issuer(iss)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param iss the JWT {@code iss} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder issuer(String iss);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2">
     * <code>sub</code></a> (subject) value.  A {@code null} value will remove the property from the Claims.
     * This is a convenience wrapper for:
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#subject(String) subject(sub)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param sub the JWT {@code sub} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder subject(String sub);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3">
     * <code>aud</code></a> (audience) value.  A {@code null} value will remove the property from the Claims.
     * This is a convenience wrapper for:
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#audience(String) audience(aud)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param aud the JWT {@code aud} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder audience(String aud);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4">
     * <code>exp</code></a> (expiration) value.  A {@code null} value will remove the property from the Claims.
     *
     * <p>A JWT obtained after this timestamp should not be used.</p>
     *
     * <p>This is a convenience wrapper for:</p>
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#expiration(Date) expiration(exp)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param exp the JWT {@code exp} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder expiration(Date exp);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5">
     * <code>nbf</code></a> (not before) value.  A {@code null} value will remove the property from the Claims.
     *
     * <p>A JWT obtained before this timestamp should not be used.</p>
     *
     * <p>This is a convenience wrapper for:</p>
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#notBefore(Date) notBefore(nbf)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param nbf the JWT {@code nbf} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder setNotBefore(Date nbf);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6">
     * <code>iat</code></a> (issued at) value.  A {@code null} value will remove the property from the Claims.
     *
     * <p>The value is the timestamp when the JWT was created.</p>
     *
     * <p>This is a convenience wrapper for:</p>
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#issuedAt(Date) issuedAt(iat)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param iat the JWT {@code iat} value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder issuedAt(Date iat);

    /**
     * Sets the JWT Claims <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7">
     * <code>jti</code></a> (JWT ID) value.  A {@code null} value will remove the property from the Claims.
     *
     * <p>The value is a CaSe-SenSiTiVe unique identifier for the JWT. If specified, this value MUST be assigned in a
     * manner that ensures that there is a negligible probability that the same value will be accidentally
     * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
     *
     * <p>This is a convenience wrapper for:</p>
     * <blockquote><pre>
     * {@link #claims()}.{@link ClaimsMutator#id(String) id(jti)}.{@link BuilderClaims#and() and()}</pre></blockquote>
     *
     * @param jti the JWT {@code jti} (id) value or {@code null} to remove the property from the Claims map.
     * @return the builder instance for method chaining.
     */
    @Override
    // for better/targeted JavaDoc
    JwtBuilder id(String jti);

    /**
     * Signs the constructed JWT with the specified key using the key's <em>recommended signature algorithm</em>
     * as defined below, producing a JWS.  If the recommended signature algorithm isn't sufficient for your needs,
     * consider using {@link #signWith(Key, SecureDigestAlgorithm)} instead.
     *
     * <p>If you are looking to invoke this method with a byte array that you are confident may be used for HMAC-SHA
     * algorithms, consider using {@link Keys Keys}.{@link Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor(bytes)} to
     * convert the byte array into a valid {@code Key}.</p>
     *
     * <p><b><a id="recsigalg">Recommended Signature Algorithm</a></b></p>
     *
     * <p>The recommended signature algorithm used with a given key is chosen based on the following:</p>
     * <table>
     * <caption>Key Recommended Signature Algorithm</caption>
     * <thead>
     * <tr>
     * <th>If the Key is a:</th>
     * <th>And:</th>
     * <th>With a key size of:</th>
     * <th>The SignatureAlgorithm used will be:</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA256")</code><sup>1</sup></td>
     * <td>256 &lt;= size &lt;= 383 <sup>2</sup></td>
     * <td>{@link Jwts.SIG#HS256 HS256}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA384")</code><sup>1</sup></td>
     * <td>384 &lt;= size &lt;= 511</td>
     * <td>{@link Jwts.SIG#HS384 HS384}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA512")</code><sup>1</sup></td>
     * <td>512 &lt;= size</td>
     * <td>{@link Jwts.SIG#HS512 HS512}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>256 &lt;= size &lt;= 383 <sup>3</sup></td>
     * <td>{@link Jwts.SIG#ES256 ES256}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>384 &lt;= size &lt;= 520 <sup>4</sup></td>
     * <td>{@link Jwts.SIG#ES384 ES384}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td><b>521</b> &lt;= size <sup>4</sup></td>
     * <td>{@link Jwts.SIG#ES512 ES512}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>2048 &lt;= size &lt;= 3071 <sup>5,6</sup></td>
     * <td>{@link Jwts.SIG#RS256 RS256}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>3072 &lt;= size &lt;= 4095 <sup>6</sup></td>
     * <td>{@link Jwts.SIG#RS384 RS384}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>4096 &lt;= size <sup>5</sup></td>
     * <td>{@link Jwts.SIG#RS512 RS512}</td>
     * </tr>
     * <tr>
     *     <td><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECKey.html">EdECKey</a><sup>7</sup></td>
     *     <td><code>instanceof {@link PrivateKey}</code></td>
     *     <td>256 || 456</td>
     *     <td>{@link Jwts.SIG#EdDSA EdDSA}</td>
     * </tr>
     * </tbody>
     * </table>
     * <p>Notes:</p>
     * <ol>
     * <li>{@code SecretKey} instances must have an {@link Key#getAlgorithm() algorithm} name equal
     * to {@code HmacSHA256}, {@code HmacSHA384} or {@code HmacSHA512}.  If not, the key bytes might not be
     * suitable for HMAC signatures will be rejected with a {@link InvalidKeyException}. </li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518,
     * Section 3.2)</a> mandates that HMAC-SHA-* signing keys <em>MUST</em> be 256 bits or greater.
     * {@code SecretKey}s with key lengths less than 256 bits will be rejected with an
     * {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.4">JWA Specification (RFC 7518,
     * Section 3.4)</a> mandates that ECDSA signing key lengths <em>MUST</em> be 256 bits or greater.
     * {@code ECKey}s with key lengths less than 256 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>The ECDSA {@code P-521} curve does indeed use keys of <b>521</b> bits, not 512 as might be expected.  ECDSA
     * keys of 384 &lt; size &lt;= 520 are suitable for ES384, while ES512 requires keys &gt;= 521 bits.  The '512' part of the
     * ES512 name reflects the usage of the SHA-512 algorithm, not the ECDSA key length.  ES512 with ECDSA keys less
     * than 521 bits will be rejected with a {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.3">JWA Specification (RFC 7518,
     * Section 3.3)</a> mandates that RSA signing key lengths <em>MUST</em> be 2048 bits or greater.
     * {@code RSAKey}s with key lengths less than 2048 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>Technically any RSA key of length &gt;= 2048 bits may be used with the
     * {@link Jwts.SIG#RS256 RS256}, {@link Jwts.SIG#RS384 RS384}, and
     * {@link Jwts.SIG#RS512 RS512} algorithms, so we assume an RSA signature algorithm based on the key
     * length to parallel similar decisions in the JWT specification for HMAC and ECDSA signature algorithms.
     * This is not required - just a convenience.</li>
     * <li><a href="https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/interfaces/EdECKey.html">EdECKey</a>s
     * require JDK &gt;= 15 or BouncyCastle in the runtime classpath.</li>
     * </ol>
     *
     * <p>This implementation does not use the {@link Jwts.SIG#PS256 PS256},
     * {@link Jwts.SIG#PS384 PS384}, or {@link Jwts.SIG#PS512 PS512} RSA variants for any
     * specified {@link RSAKey} because the the {@link Jwts.SIG#RS256 RS256},
     * {@link Jwts.SIG#RS384 RS384}, and {@link Jwts.SIG#RS512 RS512} algorithms are
     * available in the JDK by default while the {@code PS}* variants require either JDK 11 or an additional JCA
     * Provider (like BouncyCastle).  If you wish to use a {@code PS}* variant with your key, use the
     * {@link #signWith(Key, SecureDigestAlgorithm)} method instead.</p>
     *
     * <p>Finally, this method will throw an {@link InvalidKeyException} for any key that does not match the
     * heuristics and requirements documented above, since that inevitably means the Key is either insufficient,
     * unsupported, or explicitly disallowed by the JWT specification.</p>
     *
     * @param key the key to use for signing
     * @return the builder instance for method chaining.
     * @throws InvalidKeyException if the Key is insufficient, unsupported, or explicitly disallowed by the JWT
     *                             specification as described above in <em>recommended signature algorithms</em>.
     * @see Jwts.SIG
     * @see #signWith(Key, SecureDigestAlgorithm)
     * @since 0.10.0
     */
    JwtBuilder signWith(Key key) throws InvalidKeyException;

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * <p><b>Deprecation Notice: Deprecated as of 0.10.0</b></p>
     *
     * <p>Use {@link Keys Keys}.{@link Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor(bytes)} to
     * obtain the {@code Key} and then invoke {@link #signWith(Key)} or
     * {@link #signWith(Key, SecureDigestAlgorithm)}.</p>
     *
     * <p>This method will be removed in the 1.0 release.</p>
     *
     * @param alg       the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param secretKey the algorithm-specific signing key to use to digitally sign the JWT.
     * @return the builder for method chaining.
     * @throws InvalidKeyException if the Key is insufficient for the specified algorithm or explicitly disallowed by
     *                             the JWT specification.
     * @deprecated as of 0.10.0: use {@link Keys Keys}.{@link Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor(bytes)} to
     * obtain the {@code Key} and then invoke {@link #signWith(Key)} or
     * {@link #signWith(Key, SecureDigestAlgorithm)}.
     * This method will be removed in the 1.0 release.
     */
    @Deprecated
    JwtBuilder signWith(SignatureAlgorithm alg, byte[] secretKey) throws InvalidKeyException;

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * <p>This is a convenience method: the string argument is first BASE64-decoded to a byte array and this resulting
     * byte array is used to invoke {@link #signWith(SignatureAlgorithm, byte[])}.</p>
     *
     * <p><b>Deprecation Notice: Deprecated as of 0.10.0, will be removed in the 1.0 release.</b></p>
     *
     * <p>This method has been deprecated because the {@code key} argument for this method can be confusing: keys for
     * cryptographic operations are always binary (byte arrays), and many people were confused as to how bytes were
     * obtained from the String argument.</p>
     *
     * <p>This method always expected a String argument that was effectively the same as the result of the following
     * (pseudocode):</p>
     *
     * <p>{@code String base64EncodedSecretKey = base64Encode(secretKeyBytes);}</p>
     *
     * <p>However, a non-trivial number of JJWT users were confused by the method signature and attempted to
     * use raw password strings as the key argument - for example {@code with(HS256, myPassword)} - which is
     * almost always incorrect for cryptographic hashes and can produce erroneous or insecure results.</p>
     *
     * <p>See this
     * <a href="https://stackoverflow.com/questions/40252903/static-secret-as-byte-key-or-string/40274325#40274325">
     * StackOverflow answer</a> explaining why raw (non-base64-encoded) strings are almost always incorrect for
     * signature operations.</p>
     *
     * <p>To perform the correct logic with base64EncodedSecretKey strings with JJWT &gt;= 0.10.0, you may do this:</p>
     * <pre><code>
     * byte[] keyBytes = {@link Decoders Decoders}.{@link Decoders#BASE64 BASE64}.{@link Decoder#decode(Object) decode(base64EncodedSecretKey)};
     * Key key = {@link Keys Keys}.{@link Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor(keyBytes)};
     * jwtBuilder.with(key); //or {@link #signWith(Key, SignatureAlgorithm)}
     * </code></pre>
     *
     * <p>This method will be removed in the 1.0 release.</p>
     *
     * @param alg                    the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param base64EncodedSecretKey the BASE64-encoded algorithm-specific signing key to use to digitally sign the
     *                               JWT.
     * @return the builder for method chaining.
     * @throws InvalidKeyException if the Key is insufficient or explicitly disallowed by the JWT specification as
     *                             described by {@link SignatureAlgorithm#forSigningKey(Key)}.
     * @deprecated as of 0.10.0: use {@link #signWith(Key)} or {@link #signWith(Key, SignatureAlgorithm)} instead.  This
     * method will be removed in the 1.0 release.
     */
    @Deprecated
    JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey) throws InvalidKeyException;

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * <p>It is typically recommended to call the {@link #signWith(Key)} instead for simplicity.
     * However, this method can be useful if the recommended algorithm heuristics do not meet your needs or if
     * you want explicit control over the signature algorithm used with the specified key.</p>
     *
     * @param alg the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param key the algorithm-specific signing key to use to digitally sign the JWT.
     * @return the builder for method chaining.
     * @throws InvalidKeyException if the Key is insufficient or explicitly disallowed by the JWT specification for
     *                             the specified algorithm.
     * @see #signWith(Key)
     * @deprecated since 0.10.0. Use {@link #signWith(Key, SecureDigestAlgorithm)} instead.
     * This method will be removed before the 1.0 release.
     */
    @Deprecated
    JwtBuilder signWith(SignatureAlgorithm alg, Key key) throws InvalidKeyException;

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p><b>This has been deprecated since JJWT_RELEASE_VERSION.  Use
     * {@link #signWith(Key, SecureDigestAlgorithm)} instead</b>.  Standard JWA algorithms
     * are represented as instances of this new interface in the {@link Jwts.SIG}
     * algorithm registry.</p>
     *
     * <p>Signs the constructed JWT with the specified key using the specified algorithm, producing a JWS.</p>
     *
     * <p>It is typically recommended to call the {@link #signWith(Key)} instead for simplicity.
     * However, this method can be useful if the recommended algorithm heuristics do not meet your needs or if
     * you want explicit control over the signature algorithm used with the specified key.</p>
     *
     * @param key the signing key to use to digitally sign the JWT.
     * @param alg the JWS algorithm to use with the key to digitally sign the JWT, thereby producing a JWS.
     * @return the builder for method chaining.
     * @throws InvalidKeyException if the Key is insufficient or explicitly disallowed by the JWT specification for
     *                             the specified algorithm.
     * @see #signWith(Key)
     * @since 0.10.0
     * @deprecated since JJWT_RELEASE_VERSION to use the more flexible {@link #signWith(Key, SecureDigestAlgorithm)}.
     */
    @Deprecated
    JwtBuilder signWith(Key key, SignatureAlgorithm alg) throws InvalidKeyException;

    /**
     * Signs the constructed JWT with the specified key using the specified algorithm, producing a JWS.
     *
     * <p>The {@link Jwts.SIG} registry makes available all standard signature
     * algorithms defined in the JWA specification.</p>
     *
     * <p>It is typically recommended to call the {@link #signWith(Key)} instead for simplicity.
     * However, this method can be useful if the recommended algorithm heuristics do not meet your needs or if
     * you want explicit control over the signature algorithm used with the specified key.</p>
     *
     * @param key the signing key to use to digitally sign the JWT.
     * @param <K> The type of key accepted by the {@code SignatureAlgorithm}.
     * @param alg the JWS algorithm to use with the key to digitally sign the JWT, thereby producing a JWS.
     * @return the builder for method chaining.
     * @throws InvalidKeyException if the Key is insufficient or explicitly disallowed by the JWT specification for
     *                             the specified algorithm.
     * @see #signWith(Key)
     * @see Jwts.SIG
     * @since JJWT_RELEASE_VERSION
     */
    <K extends Key> JwtBuilder signWith(K key, SecureDigestAlgorithm<? super K, ?> alg) throws InvalidKeyException;

    /**
     * Encrypts the constructed JWT with the specified symmetric {@code key} using the provided {@code enc}ryption
     * algorithm, producing a JWE.  Because it is a symmetric key, the JWE recipient
     * must also have access to the same key to decrypt.
     *
     * <p>This method is a convenience method that delegates to
     * {@link #encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * based on the {@code key} argument:</p>
     * <ul>
     *     <li>If the provided {@code key} is a {@link Password Password} instance,
     *     the {@code KeyAlgorithm} used will be one of the three JWA-standard password-based key algorithms
     *      ({@link Jwts.KEY#PBES2_HS256_A128KW PBES2_HS256_A128KW},
     *      {@link Jwts.KEY#PBES2_HS384_A192KW PBES2_HS384_A192KW}, or
     *      {@link Jwts.KEY#PBES2_HS512_A256KW PBES2_HS512_A256KW}) as determined by the {@code enc} algorithm's
     *      {@link AeadAlgorithm#getKeyBitLength() key length} requirement.</li>
     *     <li>If the {@code key} is otherwise a standard {@code SecretKey}, the {@code KeyAlgorithm} will be
     *     {@link Jwts.KEY#DIRECT DIRECT}, indicating that {@code key} should be used directly with the
     *     {@code enc} algorithm.  In this case, the {@code key} argument <em>MUST</em> be of sufficient strength to
     *     use with the specified {@code enc} algorithm, otherwise an exception will be thrown during encryption. If
     *     desired, secure-random keys suitable for an {@link AeadAlgorithm} may be generated using the algorithm's
     *     {@link AeadAlgorithm#key() key()} builder.</li>
     * </ul>
     *
     * @param key the symmetric encryption key to use with the {@code enc} algorithm.
     * @param enc the {@link AeadAlgorithm} algorithm used to encrypt the JWE, usually one of the JWA-standard
     *            algorithms accessible via {@link Jwts.ENC}.
     * @return the JWE builder for method chaining.
     * @see Jwts.ENC
     */
    JwtBuilder encryptWith(SecretKey key, AeadAlgorithm enc);

    /**
     * Encrypts the constructed JWT using the specified {@code enc} algorithm with the symmetric key produced by the
     * {@code keyAlg} when invoked with the given {@code key}, producing a JWE.
     *
     * <p>This behavior can be illustrated by the following pseudocode, a rough example of what happens during
     * {@link #compact() compact}ion:</p>
     * <blockquote><pre>
     *     SecretKey encryptionKey = keyAlg.getEncryptionKey(key);           // (1)
     *     byte[] jweCiphertext = enc.encrypt(payloadBytes, encryptionKey);  // (2)</pre></blockquote>
     * <ol>
     *     <li>The {@code keyAlg} argument is first invoked with the provided {@code key} argument, resulting in a
     *         {@link SecretKey}.</li>
     *     <li>This {@code SecretKey} result is used to call the provided {@code enc} encryption algorithm argument,
     *         resulting in the final JWE ciphertext.</li>
     * </ol>
     *
     * <p>Most application developers will reference one of the JWA
     * {@link Jwts.KEY standard key algorithms} and {@link Jwts.ENC standard encryption algorithms}
     * when invoking this method, but custom implementations are also supported.</p>
     *
     * @param <K>    the type of key that must be used with the specified {@code keyAlg} instance.
     * @param key    the key used to invoke the provided {@code keyAlg} instance.
     * @param keyAlg the key management algorithm that will produce the symmetric {@code SecretKey} to use with the
     *               {@code enc} algorithm
     * @param enc    the {@link AeadAlgorithm} algorithm used to encrypt the JWE
     * @return the JWE builder for method chaining.
     * @see Jwts.ENC
     * @see Jwts.KEY
     */
    <K extends Key> JwtBuilder encryptWith(K key, KeyAlgorithm<? super K, ?> keyAlg, AeadAlgorithm enc);

    /**
     * Compresses the JWT payload using the specified {@link CompressionAlgorithm}.
     *
     * <p>If your compact JWTs are large, and you want to reduce their total size during network transmission, this
     * can be useful.  For example, when embedding JWTs  in URLs, some browsers may not support URLs longer than a
     * certain length.  Using compression can help ensure the compact JWT fits within that length.  However, NOTE:</p>
     *
     * <p><b>Compatibility Warning</b></p>
     *
     * <p>The JWT family of specifications defines compression only for JWE (JSON Web Encryption)
     * tokens.  Even so, JJWT will also support compression for JWS tokens as well if you choose to use it.
     * However, be aware that <b>if you use compression when creating a JWS token, other libraries may not be able to
     * parse that JWS token</b>.  When using compression for JWS tokens, be sure that all parties accessing the
     * JWS token support compression for JWS.</p>
     *
     * <p>Compression when creating JWE tokens however should be universally accepted for any
     * library that supports JWE.</p>
     *
     * @param alg implementation of the {@link CompressionAlgorithm} to be used.
     * @return the builder for method chaining.
     * @see Jwts.ZIP
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder compressWith(CompressionAlgorithm alg);

    /**
     * Perform Base64Url encoding during {@link #compact() compaction} with the specified Encoder.
     *
     * <p>JJWT uses a spec-compliant encoder that works on all supported JDK versions, but you may call this method
     * to specify a different encoder if you desire.</p>
     *
     * @param base64UrlEncoder the encoder to use when Base64Url-encoding
     * @return the builder for method chaining.
     * @see #encoder(Encoder)
     * @since 0.10.0
     * @deprecated since JJWT_RELEASE_VERSION in favor of the more modern builder-style
     * {@link #encoder(Encoder)} method.
     */
    @Deprecated
    JwtBuilder base64UrlEncodeWith(Encoder<byte[], String> base64UrlEncoder);

    /**
     * Perform Base64Url encoding during {@link #compact() compaction} with the specified Encoder.
     *
     * <p>JJWT uses a spec-compliant encoder that works on all supported JDK versions, but you may call this method
     * to specify a different encoder if necessar.</p>
     *
     * @param encoder the encoder to use when Base64Url-encoding
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder encoder(Encoder<byte[], String> encoder);

    /**
     * Performs Map-to-JSON serialization with the specified Serializer.  This is used by the builder to convert
     * JWT/JWS/JWE headers and claims Maps to JSON strings as required by the JWT specification.
     *
     * <p>If this method is not called, JJWT will use whatever serializer it can find at runtime, checking for the
     * presence of well-known implementations such Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the {@link #compact()} method is invoked.</p>
     *
     * @param serializer the serializer to use when converting Map objects to JSON strings.
     * @return the builder for method chaining.
     * @since 0.10.0
     * @deprecated since JJWT_RELEASE_VERSION in favor of the more modern builder-style
     * {@link #serializer(Serializer)} method.
     */
    @Deprecated
    JwtBuilder serializeToJsonWith(Serializer<Map<String, ?>> serializer);

    /**
     * Perform Map-to-JSON serialization with the specified Serializer.  This is used by the builder to convert
     * JWT/JWS/JWE headers and Claims Maps to JSON strings as required by the JWT specification.
     *
     * <p>If this method is not called, JJWT will use whatever serializer it can find at runtime, checking for the
     * presence of well-known implementations such Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the {@link #compact()} method is invoked.</p>
     *
     * @param serializer the serializer to use when converting Map objects to JSON strings.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtBuilder serializer(Serializer<Map<String, ?>> serializer);

    /**
     * Actually builds the JWT and serializes it to a compact, URL-safe string according to the
     * <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-7.1">JWT Compact Serialization</a>
     * rules.
     *
     * @return A compact URL-safe JWT string.
     */
    String compact();

    /**
     * Claims for use with a {@link JwtBuilder} that supports method chaining for standard JWT Claims parameters.
     * Once claims are configured, the associated {@link JwtBuilder} may be obtained with the {@link #and() and()}
     * method for continued configuration.
     *
     * @since JJWT_RELEASE_VERSION
     */
    interface BuilderClaims extends MapMutator<String, Object, BuilderClaims>, ClaimsMutator<BuilderClaims> {

        /**
         * Returns the associated JwtBuilder for continued configuration.
         *
         * @return the associated JwtBuilder for continued configuration.
         */
        JwtBuilder and();
    }

    /**
     * Header for use with a {@link JwtBuilder} that supports method chaining for
     * standard JWT, JWS and JWE header parameters.  Once header parameters are configured, the associated
     * {@link JwtBuilder} may be obtained with the {@link #and() and()} method for continued configuration.
     *
     * @since JJWT_RELEASE_VERSION
     */
    interface BuilderHeader extends JweHeaderMutator<BuilderHeader>, X509Builder<BuilderHeader> {

        /**
         * Returns the associated JwtBuilder for continued configuration.
         *
         * @return the associated JwtBuilder for continued configuration.
         */
        JwtBuilder and();
    }
}

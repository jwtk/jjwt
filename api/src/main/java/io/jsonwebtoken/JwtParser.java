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

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import java.io.InputStream;

/**
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 *
 * @since 0.1
 */
public interface JwtParser extends Parser<Jwt<?, ?>> {

    /**
     * Returns {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     *
     * <p>Note that if you are reasonably sure that the token is signed, it is more efficient to attempt to
     * parse the token (and catching exceptions if necessary) instead of calling this method first before parsing.</p>
     *
     * @param compact the compact serialized JWT to check
     * @return {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     */
    boolean isSigned(CharSequence compact);

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns the resulting JWT, JWS, or JWE instance.
     *
     * <p>Because it is often cumbersome to determine if the result is a JWT, JWS or JWE, or if the payload is a Claims
     * or {@code byte[]} array with {@code instanceof} checks, it may be useful to call the result's
     * {@link Jwt#accept(JwtVisitor) accept(JwtVisitor)} method for a type-safe callback approach instead of using if-then-else
     * {@code instanceof} conditionals. For example, instead of:</p>
     *
     * <blockquote><pre>
     * // NOT RECOMMENDED:
     * Jwt&lt;?,?&gt; jwt = parser.parse(input);
     * if (jwt instanceof Jwe&lt;?&gt;) {
     *     Jwe&lt;?&gt; jwe = (Jwe&lt;?&gt;)jwt;
     *     if (jwe.getPayload() instanceof Claims) {
     *         Jwe&lt;Claims&gt; claimsJwe = (Jwe&lt;Claims&gt;)jwe;
     *         // do something with claimsJwe
     *     }
     * }</pre></blockquote>
     *
     * <p>the following alternative is usually preferred:</p>
     *
     * <blockquote><pre>
     * Jwe&lt;Claims&gt; jwe = parser.parse(input).accept({@link Jwe#CLAIMS});</pre></blockquote>
     *
     * @param jwt the compact serialized JWT to parse
     * @return the parsed JWT instance
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws SecurityException        if the specified JWT string is a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace.
     * @see Jwt#accept(JwtVisitor)
     */
    Jwt<?, ?> parse(CharSequence jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException,
            SecurityException, IllegalArgumentException;

    /**
     * Deprecated since 0.12.0 in favor of calling any {@code parse*} method immediately
     * followed by invoking the parsed JWT's {@link Jwt#accept(JwtVisitor) accept} method with your preferred visitor. For
     * example:
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jwt).{@link Jwt#accept(JwtVisitor) accept}({@link JwtVisitor visitor});</pre></blockquote>
     *
     * <p>This method will be removed before the 1.0 release.</p>
     *
     * @param jwt     the compact serialized JWT to parse
     * @param handler the handler to invoke when encountering a specific type of JWT
     * @param <T>     the type of object returned from the {@code handler}
     * @return the result returned by the {@code JwtHandler}
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws SecurityException        if the specified JWT string is a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace, or if the
     *                                  {@code handler} is {@code null}.
     * @see Jwt#accept(JwtVisitor)
     * @since 0.2
     * @deprecated since 0.12.0 in favor of
     * <code>{@link #parse(CharSequence)}.{@link Jwt#accept(JwtVisitor) accept}({@link JwtVisitor visitor});</code>
     */
    @Deprecated
    <T> T parse(CharSequence jwt, JwtHandler<T> handler) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Deprecated since 0.12.0 in favor of {@link #parseUnsecuredContent(CharSequence)}.
     *
     * <p>This method will be removed before the 1.0 release.</p>
     *
     * @param jwt a compact serialized unsecured content JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unsecured content JWT
     * @throws MalformedJwtException    if the {@code jwt} string is not a valid JWT
     * @throws SignatureException       if the {@code jwt} string is actually a JWS and signature validation fails
     * @throws SecurityException        if the {@code jwt} string is actually a JWE and decryption fails
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parseUnsecuredContent(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.2
     * @deprecated since 0.12.0 in favor of {@link #parseUnsecuredContent(CharSequence)}.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    Jwt<Header, byte[]> parseContentJwt(CharSequence jwt) throws UnsupportedJwtException, MalformedJwtException,
            SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Deprecated since 0.12.0 in favor of {@link #parseUnsecuredClaims(CharSequence)}.
     *
     * <p>This method will be removed before the 1.0 release.</p>
     *
     * @param jwt a compact serialized unsecured Claims JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unsecured Claims JWT
     * @throws MalformedJwtException    if the {@code jwt} string is not a valid JWT
     * @throws SignatureException       if the {@code jwt} string is actually a JWS and signature validation fails
     * @throws SecurityException        if the {@code jwt} string is actually a JWE and decryption fails
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parseUnsecuredClaims(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.2
     * @deprecated since 0.12.0 in favor of {@link #parseUnsecuredClaims(CharSequence)}.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    Jwt<Header, Claims> parseClaimsJwt(CharSequence jwt) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Deprecated since 0.12.0 in favor of {@link #parseSignedContent(CharSequence)}.
     *
     * <p>This method will be removed before the 1.0 release.</p>
     *
     * @param jws a compact content JWS string
     * @return the parsed and validated content JWS
     * @throws UnsupportedJwtException  if the {@code jws} argument does not represent a content JWS
     * @throws MalformedJwtException    if the {@code jws} string is not a valid JWS
     * @throws SignatureException       if the {@code jws} JWS signature validation fails
     * @throws SecurityException        if the {@code jws} string is actually a JWE and decryption fails
     * @throws IllegalArgumentException if the {@code jws} string is {@code null} or empty or only whitespace
     * @see #parseSignedContent(CharSequence)
     * @see #parseEncryptedContent(CharSequence)
     * @see #parse(CharSequence)
     * @since 0.2
     * @deprecated since 0.12.0 in favor of {@link #parseSignedContent(CharSequence)}.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    Jws<byte[]> parseContentJws(CharSequence jws) throws UnsupportedJwtException, MalformedJwtException, SignatureException,
            SecurityException, IllegalArgumentException;

    /**
     * Deprecated since 0.12.0 in favor of {@link #parseSignedClaims(CharSequence)}.
     *
     * @param jws a compact Claims JWS string.
     * @return the parsed and validated Claims JWS
     * @throws UnsupportedJwtException  if the {@code claimsJws} argument does not represent an Claims JWS
     * @throws MalformedJwtException    if the {@code claimsJws} string is not a valid JWS
     * @throws SignatureException       if the {@code claimsJws} JWS signature validation fails
     * @throws SecurityException        if the {@code jws} string is actually a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code claimsJws} string is {@code null} or empty or only whitespace
     * @see #parseSignedClaims(CharSequence)
     * @see #parseEncryptedClaims(CharSequence)
     * @see #parse(CharSequence)
     * @since 0.2
     * @deprecated since 0.12.0 in favor of {@link #parseSignedClaims(CharSequence)}.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    Jws<Claims> parseClaimsJws(CharSequence jws) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
            SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Parses the {@code jwt} argument, expected to be an unsecured content JWT. If the JWT creator set
     * the (optional) {@link Header#getContentType() contentType} header value, the application may inspect that
     * value to determine how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method logically equivalent to the following:</p>
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jwt).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jwt#UNSECURED_CONTENT});</pre></blockquote>
     *
     * @param jwt a compact unsecured content JWT.
     * @return the parsed unsecured content JWT.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unsecured content JWT
     * @throws JwtException             if the {@code jwt} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jwt<Header, byte[]> parseUnsecuredContent(CharSequence jwt) throws JwtException, IllegalArgumentException;

    /**
     * Parses the {@code jwt} argument, expected to be an unsecured {@code Claims} JWT. This is a
     * convenience method logically equivalent to the following:
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jwt).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jwt#UNSECURED_CLAIMS});</pre></blockquote>
     *
     * @param jwt a compact unsecured Claims JWT.
     * @return the parsed unsecured Claims JWT.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unsecured Claims JWT
     * @throws JwtException             if the {@code jwt} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jwt<Header, Claims> parseUnsecuredClaims(CharSequence jwt) throws JwtException, IllegalArgumentException;

    /**
     * Parses the {@code jws} argument, expected to be a cryptographically-signed content JWS. If the JWS
     * creator set the (optional) {@link Header#getContentType() contentType} header value, the application may
     * inspect that value to determine how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method logically equivalent to the following:</p>
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jws).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jws#CONTENT});</pre></blockquote>
     *
     * @param jws a compact cryptographically-signed content JWS.
     * @return the parsed cryptographically-verified content JWS.
     * @throws UnsupportedJwtException  if the {@code jws} argument does not represent a signed content JWS
     * @throws JwtException             if the {@code jws} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jws} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jws<byte[]> parseSignedContent(CharSequence jws) throws JwtException, IllegalArgumentException;

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the specified {@code unencodedPayload} for signature verification.
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     *
     * <p>Note that if the JWS contains a valid unencoded Payload string (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     * @since 0.12.0
     */
    Jws<byte[]> parseSignedContent(CharSequence jws, byte[] unencodedPayload);

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the bytes from the specified {@code unencodedPayload} stream for signature verification.
     *
     * <p>Because it is not possible to know how large the {@code unencodedPayload} stream will be, the stream bytes
     * will not be buffered in memory, ensuring the resulting {@link Jws} return value's {@link Jws#getPayload()}
     * is always empty.  This is generally not a concern since the caller already has access to the stream bytes and
     * may obtain them independently before or after calling this method if they are needed otherwise.</p>
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     *
     * <p>Note that if the JWS contains a valid unencoded payload String (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification. In this case the resulting {@link Jws} return
     * value's {@link Jws#getPayload()} will contain the embedded payload String's UTF-8 bytes.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     * @since 0.12.0
     */
    Jws<byte[]> parseSignedContent(CharSequence jws, InputStream unencodedPayload);

    /**
     * Parses the {@code jws} argument, expected to be a cryptographically-signed {@code Claims} JWS. This is a
     * convenience method logically equivalent to the following:
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jws).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jws#CLAIMS});</pre></blockquote>
     *
     * @param jws a compact cryptographically-signed Claims JWS.
     * @return the parsed cryptographically-verified Claims JWS.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent a signed Claims JWT
     * @throws JwtException             if the {@code jwt} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jws<Claims> parseSignedClaims(CharSequence jws) throws JwtException, IllegalArgumentException;

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the specified {@code unencodedPayload} for signature verification.
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     *
     * <p>Note that if the JWS contains a valid unencoded payload String (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification and claims creation.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed and validated Claims JWS.
     * @throws JwtException             if parsing, signature verification, or JWT validation fails.
     * @throws IllegalArgumentException if either the {@code jws} or {@code unencodedPayload} are null or empty.
     * @since 0.12.0
     */
    Jws<Claims> parseSignedClaims(CharSequence jws, byte[] unencodedPayload) throws JwtException, IllegalArgumentException;

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the bytes from the specified {@code unencodedPayload} stream for signature verification and
     * {@link Claims} creation.
     *
     * <p><b>NOTE:</b> however, because calling this method indicates a completed
     * {@link Claims} instance is desired, the specified {@code unencodedPayload} JSON stream will be fully
     * read into a Claims instance.  If this will be problematic for your application (perhaps if you expect extremely
     * large Claims), it is recommended to use the {@link #parseSignedContent(CharSequence, InputStream)} method
     * instead.</p>
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     *
     * <p>Note that if the JWS contains a valid unencoded Payload string (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification and Claims creation.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed and validated Claims JWS.
     * @throws JwtException             if parsing, signature verification, or JWT validation fails.
     * @throws IllegalArgumentException if either the {@code jws} or {@code unencodedPayload} are null or empty.
     * @since 0.12.0
     */
    Jws<Claims> parseSignedClaims(CharSequence jws, InputStream unencodedPayload) throws JwtException, IllegalArgumentException;

    /**
     * Parses the {@code jwe} argument, expected to be an encrypted content JWE. If the JWE
     * creator set the (optional) {@link Header#getContentType() contentType} header value, the application may
     * inspect that value to determine how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method logically equivalent to the following:</p>
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jwe).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jwe#CONTENT});</pre></blockquote>
     *
     * @param jwe a compact encrypted content JWE.
     * @return the parsed decrypted content JWE.
     * @throws UnsupportedJwtException  if the {@code jwe} argument does not represent an encrypted content JWE
     * @throws JwtException             if the {@code jwe} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jwe} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jwe<byte[]> parseEncryptedContent(CharSequence jwe) throws JwtException, IllegalArgumentException;

    /**
     * Parses the {@code jwe} argument, expected to be an encrypted {@code Claims} JWE. This is a
     * convenience method logically equivalent to the following:
     *
     * <blockquote><pre>
     * {@link #parse(CharSequence) parse}(jwe).{@link Jwt#accept(JwtVisitor) accept}({@link
     * Jwe#CLAIMS});</pre></blockquote>
     *
     * @param jwe a compact encrypted Claims JWE.
     * @return the parsed decrypted Claims JWE.
     * @throws UnsupportedJwtException  if the {@code jwe} argument does not represent an encrypted Claims JWE.
     * @throws JwtException             if the {@code jwe} string cannot be parsed or validated as required.
     * @throws IllegalArgumentException if the {@code jwe} string is {@code null} or empty or only whitespace
     * @see #parse(CharSequence)
     * @see Jwt#accept(JwtVisitor)
     * @since 0.12.0
     */
    Jwe<Claims> parseEncryptedClaims(CharSequence jwe) throws JwtException, IllegalArgumentException;
}

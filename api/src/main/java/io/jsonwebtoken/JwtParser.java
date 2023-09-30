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
     * <p>This method returns a JWT, JWS, or JWE based on the parsed string.  Because it may be cumbersome to
     * determine if it is a JWT, JWS or JWE, or if the payload is a Claims or byte array with {@code instanceof} checks,
     * the {@link #parse(CharSequence, JwtHandler) parse(String,JwtHandler)} method allows for a type-safe callback approach
     * that may help reduce code or instanceof checks.</p>
     *
     * @param jwt the compact serialized JWT to parse
     * @return the specified compact serialized JWT string based on the builder's current configuration state.
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws SecurityException        if the specified JWT string is a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace.
     * @see #parse(CharSequence, JwtHandler)
     * @see #parseContentJwt(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parseContentJwe(CharSequence)
     * @see #parseClaimsJwe(CharSequence)
     */
    Jwt<?, ?> parse(CharSequence jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException,
            SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * invokes the specified {@code handler} with the resulting JWT, JWS, or JWE instance.
     *
     * <p>If you are confident of the format of the JWT before parsing, you can create an anonymous subclass using the
     * {@link io.jsonwebtoken.JwtHandlerAdapter JwtHandlerAdapter} and override only the methods you know are relevant
     * for your use case(s), for example:</p>
     *
     * <pre>
     * String compactJwt = request.getParameter("jwt"); //we are confident this is a signed JWS
     *
     * String subject = Jwts.parser().verifyWith(key).build().parse(compactJwt, new JwtHandlerAdapter&lt;String&gt;() {
     *     &#64;Override
     *     public String onClaimsJws(Jws&lt;Claims&gt; jws) {
     *         return jws.getBody().getSubject();
     *     }
     * });
     * </pre>
     *
     * <p>If you know the JWT string can be only one type of JWT, then it is even easier to invoke one of the
     * following convenience methods instead of this one:</p>
     *
     * <ul>
     * <li>{@link #parseContentJwt(CharSequence)}</li>
     * <li>{@link #parseClaimsJwt(CharSequence)}</li>
     * <li>{@link #parseContentJws(CharSequence)}</li>
     * <li>{@link #parseClaimsJws(CharSequence)}</li>
     * <li>{@link #parseContentJwe(CharSequence)}</li>
     * <li>{@link #parseClaimsJwe(CharSequence)}</li>
     * </ul>
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
     * @see #parseContentJwt(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parseContentJwe(CharSequence)
     * @see #parseClaimsJwe(CharSequence)
     * @see #parse(CharSequence)
     * @since 0.2
     */
    <T> T parse(CharSequence jwt, JwtHandler<T> handler) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns the resulting unprotected content JWT instance. If the JWT creator set the (optional)
     * {@link Header#getContentType() contentType} header value, the application may inspect that value to determine
     * how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unprotected content JWT. An unprotected content JWT has a byte array payload and it is not
     * cryptographically signed or encrypted. If the JWT creator set the (optional)
     * {@link Header#getContentType() contentType} header value, the application may inspect that value to determine
     * how to convert the byte array to the final content type as desired.</p>
     *
     * <p><b>If the compact string presented does not reflect an unprotected content JWT with byte array payload,
     * an {@link UnsupportedJwtException} will be thrown.</b></p>
     *
     * @param jwt a compact serialized unprotected content JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unprotected content JWT
     * @throws MalformedJwtException    if the {@code jwt} string is not a valid JWT
     * @throws SignatureException       if the {@code jwt} string is actually a JWS and signature validation fails
     * @throws SecurityException        if the {@code jwt} string is actually a JWE and decryption fails
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since 0.2
     */
    Jwt<Header, byte[]> parseContentJwt(CharSequence jwt) throws UnsupportedJwtException, MalformedJwtException,
            SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns the resulting unprotected Claims JWT instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unprotected Claims JWT. An unprotected Claims JWT has a {@link Claims} payload and it is not cryptographically
     * signed or encrypted.</p>
     *
     * <p><b>If the compact string presented does not reflect an unprotected Claims JWT, an
     * {@link UnsupportedJwtException} will be thrown.</b></p>
     *
     * @param jwt a compact serialized unprotected Claims JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code jwt} argument does not represent an unprotected Claims JWT
     * @throws MalformedJwtException    if the {@code jwt} string is not a valid JWT
     * @throws SignatureException       if the {@code jwt} string is actually a JWS and signature validation fails
     * @throws SecurityException        if the {@code jwt} string is actually a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code jwt} string is {@code null} or empty or only whitespace
     * @see #parseContentJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since 0.2
     */
    Jwt<Header, Claims> parseClaimsJwt(CharSequence jwt) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWS string based on the builder's current configuration state and
     * returns the resulting content JWS instance. If the JWT creator set the (optional)
     * {@link Header#getContentType() contentType} header value, the application may inspect that value to determine
     * how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * content JWS. A content JWS is a JWT with a byte array payload that has been cryptographically signed.</p>
     *
     * <p><b>If the compact string presented does not reflect a content JWS, an {@link UnsupportedJwtException}
     * will be thrown.</b></p>
     *
     * @param jws a compact serialized JWS string.
     * @return the {@link Jws Jws} instance that reflects the specified compact JWS string.
     * @throws UnsupportedJwtException  if the {@code jws} argument does not represent a content JWS
     * @throws MalformedJwtException    if the {@code jws} string is not a valid JWS
     * @throws SignatureException       if the {@code jws} JWS signature validation fails
     * @throws SecurityException        if the {@code jws} string is actually a JWE and decryption fails
     * @throws IllegalArgumentException if the {@code jws} string is {@code null} or empty or only whitespace
     * @see #parseContentJwt(CharSequence)
     * @see #parseContentJwe(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parseClaimsJwe(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since 0.2
     */
    Jws<byte[]> parseContentJws(CharSequence jws) throws UnsupportedJwtException, MalformedJwtException, SignatureException,
            SecurityException, IllegalArgumentException;

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the specified {@code unencodedPayload} for signature verification.
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     * <p>Note that if the JWS contains a valid unencoded Payload string (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     */
    Jws<byte[]> parseContentJws(CharSequence jws, byte[] unencodedPayload);

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the specified {@code unencodedPayload} for signature verification.
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     * <p>Note that if the JWS contains a valid unencoded payload String (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification and claims creation.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     */
    Jws<Claims> parseClaimsJws(CharSequence jws, byte[] unencodedPayload);

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
     * <p>Note that if the JWS contains a valid unencoded payload String (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification. In this case the resulting {@link Jws} return
     * value's {@link Jws#getPayload()} will contain the embedded payload String's UTF-8 bytes.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     */
    Jws<byte[]> parseContentJws(CharSequence jws, InputStream unencodedPayload);

    /**
     * Parses a JWS known to use the
     * <a href="https://datatracker.ietf.org/doc/html/rfc7797">RFC 7797: JSON Web Signature (JWS) Unencoded Payload
     * Option</a>, using the bytes from the specified {@code unencodedPayload} stream for signature verification and
     * {@link Claims} creation.
     *
     * <p><b>NOTE:</b> however, because calling this method indicates a completed
     * {@link Claims} instance is desired, the specified {@code unencodedPayload} JSON stream will be fully
     * read into a Claims instance.  If this will be problematic for your application (perhaps if you expect extremely
     * large Claims), it is recommended to use the {@link #parseContentJws(CharSequence, InputStream)} method instead.</p>
     *
     * <p><b>Unencoded Non-Detached Payload</b></p>
     * <p>Note that if the JWS contains a valid unencoded Payload string (what RFC 7797 calls an
     * &quot;<a href="https://datatracker.ietf.org/doc/html/rfc7797#section-5.2">unencoded non-detached
     * payload</a>&quot;, the {@code unencodedPayload} method argument will be ignored, as the JWS already includes
     * the payload content necessary for signature verification and Claims creation.</p>
     *
     * @param jws              the Unencoded Payload JWS to parse.
     * @param unencodedPayload the JWS's associated required unencoded payload used for signature verification.
     * @return the parsed Unencoded Payload.
     */
    Jws<Claims> parseClaimsJws(CharSequence jws, InputStream unencodedPayload);

    /**
     * Parses the specified compact serialized JWS string based on the builder's current configuration state and
     * returns the resulting Claims JWS instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * Claims JWS. A Claims JWS is a JWT with a {@link Claims} payload that has been cryptographically signed.</p>
     *
     * <p><b>If the compact string presented does not reflect a Claims JWS, an {@link UnsupportedJwtException} will be
     * thrown.</b></p>
     *
     * @param jws a compact serialized Claims JWS string.
     * @return the {@link Jws Jws} instance that reflects the specified compact Claims JWS string.
     * @throws UnsupportedJwtException  if the {@code claimsJws} argument does not represent an Claims JWS
     * @throws MalformedJwtException    if the {@code claimsJws} string is not a valid JWS
     * @throws SignatureException       if the {@code claimsJws} JWS signature validation fails
     * @throws SecurityException        if the {@code jws} string is actually a JWE and decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code claimsJws} string is {@code null} or empty or only whitespace
     * @see #parseContentJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseContentJwe(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseClaimsJwe(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since 0.2
     */
    Jws<Claims> parseClaimsJws(CharSequence jws) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
            SignatureException, SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWE string based on the builder's current configuration state and
     * returns the resulting content JWE instance. If the JWT creator set the (optional)
     * {@link Header#getContentType() contentType} header value, the application may inspect that value to determine
     * how to convert the byte array to the final content type as desired.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * content JWE. A content JWE is a JWT with a byte array payload that has been encrypted.</p>
     *
     * <p><b>If the compact string presented does not reflect a content JWE, an {@link UnsupportedJwtException}
     * will be thrown.</b></p>
     *
     * @param jwe a compact serialized JWE string.
     * @return the {@link Jwe Jwe} instance that reflects the specified compact JWE string.
     * @throws UnsupportedJwtException  if the {@code jwe} argument does not represent a content JWE
     * @throws MalformedJwtException    if the {@code jwe} string is not a valid JWE
     * @throws SecurityException        if the {@code jwe} JWE decryption fails
     * @throws IllegalArgumentException if the {@code jwe} string is {@code null} or empty or only whitespace
     * @see #parseContentJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parseClaimsJwe(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since JJWT_RELEASE_VERSION
     */
    Jwe<byte[]> parseContentJwe(CharSequence jwe) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
            SecurityException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWE string based on the builder's current configuration state and
     * returns the resulting Claims JWE instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * Claims JWE. A Claims JWE is a JWT with a {@link Claims} payload that has been encrypted.</p>
     *
     * <p><b>If the compact string presented does not reflect a Claims JWE, an {@link UnsupportedJwtException} will be
     * thrown.</b></p>
     *
     * @param jwe a compact serialized Claims JWE string.
     * @return the {@link Jwe Jwe} instance that reflects the specified compact Claims JWE string.
     * @throws UnsupportedJwtException  if the {@code claimsJwe} argument does not represent a Claims JWE
     * @throws MalformedJwtException    if the {@code claimsJwe} string is not a valid JWE
     * @throws SignatureException       if the {@code claimsJwe} JWE decryption fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWE and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code claimsJwe} string is {@code null} or empty or only whitespace
     * @see #parseContentJwt(CharSequence)
     * @see #parseContentJws(CharSequence)
     * @see #parseContentJwe(CharSequence)
     * @see #parseClaimsJwt(CharSequence)
     * @see #parseClaimsJws(CharSequence)
     * @see #parse(CharSequence, JwtHandler)
     * @see #parse(CharSequence)
     * @since JJWT_RELEASE_VERSION
     */
    Jwe<Claims> parseClaimsJwe(CharSequence jwe) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
            SecurityException, IllegalArgumentException;
}

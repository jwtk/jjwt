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

import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

/**
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 *
 * @since 0.1
 */
public interface JwtParser {

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
    boolean isSigned(String compact);

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns the resulting JWT, JWS, or JWE instance.
     *
     * <p>This method returns a JWT, JWS, or JWE based on the parsed string.  Because it may be cumbersome to
     * determine if it is a JWT, JWS or JWE, or if the payload is a Claims or byte array with {@code instanceof} checks,
     * the {@link #parse(String, JwtHandler) parse(String,JwtHandler)} method allows for a type-safe callback approach
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
     * @see #parse(String, JwtHandler)
     * @see #parseContentJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parseContentJws(String)
     * @see #parseClaimsJws(String)
     * @see #parseContentJwe(String)
     * @see #parseClaimsJwe(String)
     */
    Jwt<?, ?> parse(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException,
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
     * <li>{@link #parseContentJwt(String)}</li>
     * <li>{@link #parseClaimsJwt(String)}</li>
     * <li>{@link #parseContentJws(String)}</li>
     * <li>{@link #parseClaimsJws(String)}</li>
     * <li>{@link #parseContentJwe(String)}</li>
     * <li>{@link #parseClaimsJwe(String)}</li>
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
     * @see #parseContentJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parseContentJws(String)
     * @see #parseClaimsJws(String)
     * @see #parseContentJwe(String)
     * @see #parseClaimsJwe(String)
     * @see #parse(String)
     * @since 0.2
     */
    <T> T parse(String jwt, JwtHandler<T> handler) throws ExpiredJwtException, UnsupportedJwtException,
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
     * @see #parseClaimsJwt(String)
     * @see #parseContentJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jwt<Header, byte[]> parseContentJwt(String jwt) throws UnsupportedJwtException, MalformedJwtException,
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
     * @see #parseContentJwt(String)
     * @see #parseContentJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jwt<Header, Claims> parseClaimsJwt(String jwt) throws ExpiredJwtException, UnsupportedJwtException,
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
     * @see #parseContentJwt(String)
     * @see #parseContentJwe(String)
     * @see #parseClaimsJwt(String)
     * @see #parseClaimsJws(String)
     * @see #parseClaimsJwe(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jws<byte[]> parseContentJws(String jws) throws UnsupportedJwtException, MalformedJwtException, SignatureException,
            SecurityException, IllegalArgumentException;

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
     * @see #parseContentJwt(String)
     * @see #parseContentJws(String)
     * @see #parseContentJwe(String)
     * @see #parseClaimsJwt(String)
     * @see #parseClaimsJwe(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jws<Claims> parseClaimsJws(String jws) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
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
     * @see #parseContentJwt(String)
     * @see #parseContentJws(String)
     * @see #parseClaimsJwt(String)
     * @see #parseClaimsJws(String)
     * @see #parseClaimsJwe(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since JJWT_RELEASE_VERSION
     */
    Jwe<byte[]> parseContentJwe(String jwe) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
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
     * @see #parseContentJwt(String)
     * @see #parseContentJws(String)
     * @see #parseContentJwe(String)
     * @see #parseClaimsJwt(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since JJWT_RELEASE_VERSION
     */
    Jwe<Claims> parseClaimsJwe(String jwe) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
            SecurityException, IllegalArgumentException;
}

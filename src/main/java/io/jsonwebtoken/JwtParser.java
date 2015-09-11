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

import java.security.Key;
import java.util.Date;

/**
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 *
 * @since 0.1
 */
public interface JwtParser {

    public static final char SEPARATOR_CHAR = '.';

    /**
     * Sets the expected value for the iss registered claim. If the actual content of the JWT does not match
     * (including if it's empty), then an exception will be thrown
     *
     * @param issuer the string representing the expected value for the iss (issuer) claim of the JWT
     * @return the parser for method chaining.
     */
    JwtParser setIssuer(String issuer);

    /**
     * Sets the expected value for the aud registered claim. If the actual content of the JWT does not match
     * (including if it's empty), then an exception will be thrown
     *
     * @param audience the string representing the expected value for the aud (audience) claim of the JWT
     * @return the parser for method chaining.
     */
    JwtParser setAudience(String audience);

    /**
     * Sets the expected value for the sub registered claim. If the actual content of the JWT does not match
     * (including if it's empty), then an exception will be thrown
     *
     * @param subject the string representing the expected value for the sub (subject) claim of the JWT
     * @return the parser for method chaining.
     */
    JwtParser setSubject(String subject);

    /**
     * Sets the expected value for the iat registered claim. If the actual content of the JWT does not match
     * (including if it's empty), then an exception will be thrown
     *
     * @param issuedAt the date representing the expected value for the iat (issued at) claim of the JWT
     * @return the parser for method chaining.
     */
    JwtParser setIssuedAt(Date issuedAt);


    /**
     * Sets the expected value for the jti registered claim. If the actual content of the JWT does not match
     * (including if it's empty), then an exception will be thrown
     *
     * @param id the string representing the expected value for the jti (jwt id) claim of the JWT
     * @return the parser for method chaining.
     */
    JwtParser setId(String id);

    /**
     * Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.
     *
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * <p>This method overwrites any previously set key.</p>
     *
     * @param key the algorithm-specific signature verification key used to validate any discovered JWS digital
     *            signature.
     * @return the parser for method chaining.
     */
    JwtParser setSigningKey(byte[] key);

    /**
     * Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.
     *
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * <p>This method overwrites any previously set key.</p>
     *
     * <p>This is a convenience method: the string argument is first BASE64-decoded to a byte array and this resulting
     * byte array is used to invoke {@link #setSigningKey(byte[])}.</p>
     *
     * @param base64EncodedKeyBytes the BASE64-encoded algorithm-specific signature verification key to use to validate
     *                              any discovered JWS digital signature.
     * @return the parser for method chaining.
     */
    JwtParser setSigningKey(String base64EncodedKeyBytes);

    /**
     * Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.
     *
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * <p>This method overwrites any previously set key.</p>
     *
     * <p>This is a convenience method: the string argument is first BASE64-decoded to a byte array and this resulting
     * byte array is used to invoke {@link #setSigningKey(byte[])}.</p>
     *
     * @param key the algorithm-specific signature verification key to use to validate any discovered JWS digital
     *            signature.
     * @return the parser for method chaining.
     */
    JwtParser setSigningKey(Key key);

    /**
     * Sets the {@link SigningKeyResolver} used to acquire the <code>signing key</code> that should be used to verify
     * a JWS's signature.  If the parsed String is not a JWS (no signature), this resolver is not used.
     *
     * <p>Specifying a {@code SigningKeyResolver} is necessary when the signing key is not already known before parsing
     * the JWT and the JWT header or payload (plaintext body or Claims) must be inspected first to determine how to
     * look up the signing key.  Once returned by the resolver, the JwtParser will then verify the JWS signature with the
     * returned key.  For example:</p>
     *
     * <pre>
     * Jws&lt;Claims&gt; jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
     *         &#64;Override
     *         public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
     *             //inspect the header or claims, lookup and return the signing key
     *             return getSigningKey(header, claims); //implement me
     *         }})
     *     .parseClaimsJws(compact);
     * </pre>
     *
     * <p>A {@code SigningKeyResolver} is invoked once during parsing before the signature is verified.</p>
     *
     * <p>This method should only be used if a signing key is not provided by the other {@code setSigningKey*} builder
     * methods.</p>
     *
     * @param signingKeyResolver the signing key resolver used to retrieve the signing key.
     * @return the parser for method chaining.
     * @since 0.4
     */
    JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    /**
     * Returns {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     *
     * <p>Note that if you are reasonably sure that the token is signed, it is more efficient to attempt to
     * parse the token (and catching exceptions if necessary) instead of calling this method first before parsing.</p>
     *
     * @param jwt the compact serialized JWT to check
     * @return {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     */
    boolean isSigned(String jwt);

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns the resulting JWT or JWS instance.
     *
     * <p>This method returns a JWT or JWS based on the parsed string.  Because it may be cumbersome to determine if it
     * is a JWT or JWS, or if the body/payload is a Claims or String with {@code instanceof} checks, the
     * {@link #parse(String, JwtHandler) parse(String,JwtHandler)} method allows for a type-safe callback approach that
     * may help reduce code or instanceof checks.</p>
     *
     * @param jwt the compact serialized JWT to parse
     * @return the specified compact serialized JWT string based on the builder's current configuration state.
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid
     *                                  JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace.
     * @see #parse(String, JwtHandler)
     * @see #parsePlaintextJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     */
    Jwt parse(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * invokes the specified {@code handler} with the resulting JWT or JWS instance.
     *
     * <p>If you are confident of the format of the JWT before parsing, you can create an anonymous subclass using the
     * {@link io.jsonwebtoken.JwtHandlerAdapter JwtHandlerAdapter} and override only the methods you know are relevant
     * for your use case(s), for example:</p>
     *
     * <pre>
     * String compactJwt = request.getParameter("jwt"); //we are confident this is a signed JWS
     *
     * String subject = Jwts.parser().setSigningKey(key).parse(compactJwt, new JwtHandlerAdapter&lt;String&gt;() {
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
     * <li>{@link #parsePlaintextJwt(String)}</li>
     * <li>{@link #parseClaimsJwt(String)}</li>
     * <li>{@link #parsePlaintextJws(String)}</li>
     * <li>{@link #parseClaimsJws(String)}</li>
     * </ul>
     *
     * @param jwt the compact serialized JWT to parse
     * @return the result returned by the {@code JwtHandler}
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace, or if the
     *                                  {@code handler} is {@code null}.
     * @see #parsePlaintextJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String)
     * @since 0.2
     */
    <T> T parse(String jwt, JwtHandler<T> handler)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns
     * the resulting unsigned plaintext JWT instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unsigned plaintext JWT. An unsigned plaintext JWT has a String (non-JSON) body payload and it is not
     * cryptographically signed.</p>
     *
     * <p><b>If the compact string presented does not reflect an unsigned plaintext JWT with non-JSON string body,
     * an {@link UnsupportedJwtException} will be thrown.</b></p>
     *
     * @param plaintextJwt a compact serialized unsigned plaintext JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code plaintextJwt} argument does not represent an unsigned plaintext
     *                                  JWT
     * @throws MalformedJwtException    if the {@code plaintextJwt} string is not a valid JWT
     * @throws SignatureException       if the {@code plaintextJwt} string is actually a JWS and signature validation
     *                                  fails
     * @throws IllegalArgumentException if the {@code plaintextJwt} string is {@code null} or empty or only whitespace
     * @see #parseClaimsJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jwt<Header, String> parsePlaintextJwt(String plaintextJwt)
        throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the builder's current configuration state and
     * returns
     * the resulting unsigned plaintext JWT instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unsigned Claims JWT. An unsigned Claims JWT has a {@link Claims} body and it is not cryptographically
     * signed.</p>
     *
     * <p><b>If the compact string presented does not reflect an unsigned Claims JWT, an
     * {@link UnsupportedJwtException} will be thrown.</b></p>
     *
     * @param claimsJwt a compact serialized unsigned Claims JWT string.
     * @return the {@link Jwt Jwt} instance that reflects the specified compact JWT string.
     * @throws UnsupportedJwtException  if the {@code claimsJwt} argument does not represent an unsigned Claims JWT
     * @throws MalformedJwtException    if the {@code claimsJwt} string is not a valid JWT
     * @throws SignatureException       if the {@code claimsJwt} string is actually a JWS and signature validation
     *                                  fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code claimsJwt} string is {@code null} or empty or only whitespace
     * @see #parsePlaintextJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jwt<Header, Claims> parseClaimsJwt(String claimsJwt)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWS string based on the builder's current configuration state and
     * returns
     * the resulting plaintext JWS instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * plaintext JWS. A plaintext JWS is a JWT with a String (non-JSON) body (payload) that has been
     * cryptographically signed.</p>
     *
     * <p><b>If the compact string presented does not reflect a plaintext JWS, an {@link UnsupportedJwtException}
     * will be thrown.</b></p>
     *
     * @param plaintextJws a compact serialized JWS string.
     * @return the {@link Jws Jws} instance that reflects the specified compact JWS string.
     * @throws UnsupportedJwtException  if the {@code plaintextJws} argument does not represent an plaintext JWS
     * @throws MalformedJwtException    if the {@code plaintextJws} string is not a valid JWS
     * @throws SignatureException       if the {@code plaintextJws} JWS signature validation fails
     * @throws IllegalArgumentException if the {@code plaintextJws} string is {@code null} or empty or only whitespace
     * @see #parsePlaintextJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jws<String> parsePlaintextJws(String plaintextJws)
        throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWS string based on the builder's current configuration state and
     * returns
     * the resulting Claims JWS instance.
     *
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * Claims JWS. A Claims JWS is a JWT with a {@link Claims} body that has been cryptographically signed.</p>
     *
     * <p><b>If the compact string presented does not reflect a Claims JWS, an {@link UnsupportedJwtException} will be
     * thrown.</b></p>
     *
     * @param claimsJws a compact serialized Claims JWS string.
     * @return the {@link Jws Jws} instance that reflects the specified compact Claims JWS string.
     * @throws UnsupportedJwtException  if the {@code claimsJws} argument does not represent an Claims JWS
     * @throws MalformedJwtException    if the {@code claimsJws} string is not a valid JWS
     * @throws SignatureException       if the {@code claimsJws} JWS signature validation fails
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the {@code claimsJws} string is {@code null} or empty or only whitespace
     * @see #parsePlaintextJwt(String)
     * @see #parseClaimsJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parse(String)
     * @since 0.2
     */
    Jws<Claims> parseClaimsJws(String claimsJws)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;
}

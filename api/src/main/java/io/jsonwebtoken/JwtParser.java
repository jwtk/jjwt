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

import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 *
 * @since 0.1
 */
@SuppressWarnings("DeprecatedIsStillUsed")
public interface JwtParser {

    /**
     * Deprecated - this was an implementation detail accidentally added to the public interface. This
     * will be removed in a future release.
     *
     * @deprecated since JJWT_RELEASE_VERSION, to be removed in a future relase.
     */
    @Deprecated
    char SEPARATOR_CHAR = '.';

    /**
     * Ensures that the specified {@code jti} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param id the {@code jti} value that must exist in the parsed JWT.
     * @return the parser method for chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireId(String)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireId(String id);

    /**
     * Ensures that the specified {@code sub} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param subject the {@code sub} value that must exist in the parsed JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireSubject(String)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireSubject(String subject);

    /**
     * Ensures that the specified {@code aud} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param audience the {@code aud} value that must exist in the parsed JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireAudience(String)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireAudience(String audience);

    /**
     * Ensures that the specified {@code iss} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param issuer the {@code iss} value that must exist in the parsed JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireIssuer(String)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireIssuer(String issuer);

    /**
     * Ensures that the specified {@code iat} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param issuedAt the {@code iat} value that must exist in the parsed JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireIssuedAt(Date)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireIssuedAt(Date issuedAt);

    /**
     * Ensures that the specified {@code exp} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param expiration the {@code exp} value that must exist in the parsed JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireExpiration(Date)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireExpiration(Date expiration);

    /**
     * Ensures that the specified {@code nbf} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param notBefore the {@code nbf} value that must exist in the parsed JWT.
     * @return the parser for method chaining
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#requireNotBefore(Date)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser requireNotBefore(Date notBefore);

    /**
     * Ensures that the specified {@code claimName} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param claimName the name of a claim that must exist in the parsed JWT.
     * @param value     the value that must exist for the specified {@code claimName} in the JWT.
     * @return the parser for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     * @deprecated see {@link JwtParserBuilder#require(String, Object)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser require(String claimName, Object value);

    /**
     * Sets the {@link Clock} that determines the timestamp to use when validating the parsed JWT.
     * The parser uses a default Clock implementation that simply returns {@code new Date()} when called.
     *
     * @param clock a {@code Clock} object to return the timestamp to use when validating the parsed JWT.
     * @return the parser for method chaining.
     * @since 0.7.0
     * @deprecated see {@link JwtParserBuilder#setClock(Clock)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setClock(Clock clock);

    /**
     * Sets the amount of clock skew in seconds to tolerate when verifying the local time against the {@code exp}
     * and {@code nbf} claims.
     *
     * @param seconds the number of seconds to tolerate for clock skew when verifying {@code exp} or {@code nbf} claims.
     * @return the parser for method chaining.
     * @throws IllegalArgumentException if {@code seconds} is a value greater than {@code Long.MAX_VALUE / 1000} as
     *                                  any such value would cause numeric overflow when multiplying by 1000 to obtain a millisecond value.
     * @since 0.7.0
     * @deprecated see {@link JwtParserBuilder#setAllowedClockSkewSeconds(long)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException;

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
     * @deprecated in favor of {@link JwtParserBuilder#verifyWith(Key)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
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
     * <p><b>Deprecation Notice: Deprecated as of 0.10.0, will be removed in 1.0.0</b></p>
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
     * use raw password strings as the key argument - for example {@code setSigningKey(myPassword)} - which is
     * almost always incorrect for cryptographic hashes and can produce erroneous or insecure results.</p>
     *
     * <p>See this
     * <a href="https://stackoverflow.com/questions/40252903/static-secret-as-byte-key-or-string/40274325#40274325">
     * StackOverflow answer</a> explaining why raw (non-base64-encoded) strings are almost always incorrect for
     * signature operations.</p>
     *
     * <p>Finally, please use the {@link #setSigningKey(Key) setSigningKey(Key)} instead, as this method and the
     * {@code byte[]} variant will be removed before the 1.0.0 release.</p>
     *
     * @param base64EncodedSecretKey the BASE64-encoded algorithm-specific signature verification key to use to validate
     *                               any discovered JWS digital signature.
     * @return the parser for method chaining.
     * @deprecated in favor of {@link JwtParserBuilder#verifyWith(Key)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setSigningKey(String base64EncodedSecretKey);

    /**
     * Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.
     *
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * <p>This method overwrites any previously set key.</p>
     *
     * @param key the algorithm-specific signature verification key to use to validate any discovered JWS digital
     *            signature.
     * @return the parser for method chaining.
     * @deprecated in favor of {@link JwtParserBuilder#verifyWith(Key)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setSigningKey(Key key);

    /**
     * Sets the {@link SigningKeyResolver} used to acquire the <code>signing key</code> that should be used to verify
     * a JWS's signature.  If the parsed String is not a JWS (no signature), this resolver is not used.
     *
     * <p>Specifying a {@code SigningKeyResolver} is necessary when the signing key is not already known before parsing
     * the JWT and the JWT header or payload (content byte array or Claims) must be inspected first to determine how to
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
     * @deprecated in favor of {@link JwtParserBuilder#setKeyLocator(Locator)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    // TODO: remove for 1.0
    JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    /**
     * Sets the {@link CompressionCodecResolver} used to acquire the {@link CompressionCodec} that should be used to
     * decompress the JWT payload. If the parsed JWT is not compressed, this resolver is not used.
     *
     * <p><b>NOTE:</b> Compression is not defined by the JWS Specification - only the JWE Specification - and it is
     * not expected that other libraries (including JJWT versions &lt; 0.6.0) are able to consume a compressed JWS
     * payload correctly.  This method is only useful if the compact JWT was compressed with JJWT &gt;= 0.6.0 or another
     * library that you know implements the same behavior.</p>
     *
     * <p><b>Default Support</b></p>
     *
     * <p>JJWT's default {@link JwtParser} implementation supports both the {@link Jwts.ZIP#DEF DEFLATE}
     * and {@link Jwts.ZIP#GZIP GZIP} algorithms by default - you do not need to
     * specify a {@code CompressionCodecResolver} in these cases.</p>
     * <p>However, if you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you may implement
     * your own {@link CompressionCodecResolver} and specify that via this method and also when
     * {@link io.jsonwebtoken.JwtBuilder#compressWith(io.jsonwebtoken.io.CompressionAlgorithm) building} JWTs.</p>
     *
     * @param compressionCodecResolver the compression codec resolver used to decompress the JWT payload.
     * @return the parser for method chaining.
     * @since 0.6.0
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link JwtParserBuilder#addCompressionAlgorithms(Collection)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver);

    /**
     * Perform Base64Url decoding with the specified Decoder
     *
     * <p>JJWT uses a spec-compliant decoder that works on all supported JDK versions, but you may call this method
     * to specify a different decoder if you desire.</p>
     *
     * @param base64UrlDecoder the decoder to use when Base64Url-decoding
     * @return the parser for method chaining.
     * @since 0.10.0
     * @deprecated see {@link JwtParserBuilder#base64UrlDecodeWith(Decoder)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder);

    /**
     * Uses the specified deserializer to convert JSON Strings (UTF-8 byte arrays) into Java Map objects.  This is
     * used by the parser after Base64Url-decoding to convert JWT/JWS/JWT JSON headers and claims into Java Map
     * objects.
     *
     * <p>If this method is not called, JJWT will use whatever deserializer it can find at runtime, checking for the
     * presence of well-known implementations such Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when one of the various {@code parse}* methods is
     * invoked.</p>
     *
     * @param deserializer the deserializer to use when converting JSON Strings (UTF-8 byte arrays) into Map objects.
     * @return the parser for method chaining.
     * @since 0.10.0
     * @deprecated see {@link JwtParserBuilder#deserializeJsonWith(Deserializer)} )}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser deserializeJsonWith(Deserializer<Map<String, ?>> deserializer);

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

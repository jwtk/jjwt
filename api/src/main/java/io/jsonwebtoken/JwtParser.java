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
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.util.Date;
import java.util.Map;

/**
 * A parser for reading JWT strings, used to convert them into a {@link Jwt} object representing the expanded JWT.
 *
 * <p>Several parsing methods are provided, allowing to parse signed and unsigned tokens, with JSON payload data
 * (represented as {@link Claims}) or non-JSON payload data (represented as {@code String} and called 'plaintext'
 * in the following):
 * <ul>
 * <li>Unsigned tokens:<ul>
 * <li>{@link #parseClaimsUnsignedJwt(String)}</li>
 * <li>{@link #parsePlaintextUnsignedJwt(String)}</li>
 * </ul></li>
 * <li>Signed tokens (JWS):<ul>
 * <li>{@link #parseClaimsJws(String)}</li>
 * <li>{@link #parsePlaintextJws(String)}</li>
 * </ul></li>
 * </ul>
 *
 * <p>If it is unknown in advance whether a token will be signed or whether its payload consists of JSON data,
 * the following parsing methods can be used. However, when only signed tokens should be accepted, the caller
 * is responsible for rejecting unsigned tokens, respectively has to use a {@code handler} which rejects unsigned
 * tokens.
 * <ul>
 * <li>{@link #parseSignedOrUnsigned(String)}</li>
 * <li>{@link #parse(String, JwtHandler)}</li>
 * </ul>
 *
 * @since 0.1
 */
public interface JwtParser {

    public static final char SEPARATOR_CHAR = '.';

    /**
     * Ensures that the specified {@code jti} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param id
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
     * @param subject
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
     * @param audience
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
     * @param issuer
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
     * @param issuedAt
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
     * @param expiration
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
     * @param notBefore
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
     * @param claimName
     * @param value
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
     * @since 0.7.0
     * @throws IllegalArgumentException if {@code seconds} is a value greater than {@code Long.MAX_VALUE / 1000} as
     * any such value would cause numeric overflow when multiplying by 1000 to obtain a millisecond value.
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
     * <p>
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     * <p>
     * <p>This method overwrites any previously set key.</p>
     *
     * @param key the algorithm-specific signature verification key used to validate any discovered JWS digital
     *            signature.
     * @return the parser for method chaining.
     * @deprecated see {@link JwtParserBuilder#setSigningKey(byte[])}.
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
     * <h4>Deprecation Notice: Deprecated as of 0.10.0, will be removed in 1.0.0</h4>
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
     * @deprecated see {@link JwtParserBuilder#setSigningKey(String)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setSigningKey(String base64EncodedSecretKey);

    /**
     * Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.
     * <p>
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     * <p>
     * <p>This method overwrites any previously set key.</p>
     *
     * @param key the algorithm-specific signature verification key to use to validate any discovered JWS digital
     *            signature.
     * @return the parser for method chaining.
     * @deprecated see {@link JwtParserBuilder#setSigningKey(Key)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setSigningKey(Key key);

    /**
     * Sets the {@link SigningKeyResolver} used to acquire the <code>signing key</code> that should be used to verify
     * a JWS's signature.  If the parsed String is not a JWS (no signature), this resolver is not used.
     * <p>
     * <p>Specifying a {@code SigningKeyResolver} is necessary when the signing key is not already known before parsing
     * the JWT and the JWT header or payload (plaintext body or Claims) must be inspected first to determine how to
     * look up the signing key.  Once returned by the resolver, the JwtParser will then verify the JWS signature with the
     * returned key.  For example:</p>
     * <p>
     * <pre>
     * Jws&lt;Claims&gt; jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
     *         &#64;Override
     *         public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
     *             //inspect the header or claims, lookup and return the signing key
     *             return getSigningKey(header, claims); //implement me
     *         }})
     *     .parseClaimsJws(compact);
     * </pre>
     * <p>
     * <p>A {@code SigningKeyResolver} is invoked once during parsing before the signature is verified.</p>
     * <p>
     * <p>This method should only be used if a signing key is not provided by the other {@code setSigningKey*} builder
     * methods.</p>
     *
     * @param signingKeyResolver the signing key resolver used to retrieve the signing key.
     * @return the parser for method chaining.
     * @since 0.4
     * @deprecated see {@link JwtParserBuilder#setSigningKeyResolver(SigningKeyResolver)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    /**
     * Sets the {@link CompressionCodecResolver} used to acquire the {@link CompressionCodec} that should be used to
     * decompress the JWT body. If the parsed JWT is not compressed, this resolver is not used.
     * <p><b>NOTE:</b> Compression is not defined by the JWT Specification, and it is not expected that other libraries
     * (including JJWT versions &lt; 0.6.0) are able to consume a compressed JWT body correctly.  This method is only
     * useful if the compact JWT was compressed with JJWT &gt;= 0.6.0 or another library that you know implements
     * the same behavior.</p>
     * <h3>Default Support</h3>
     * <p>JJWT's default {@link JwtParser} implementation supports both the
     * {@link CompressionCodecs#DEFLATE DEFLATE}
     * and {@link CompressionCodecs#GZIP GZIP} algorithms by default - you do not need to
     * specify a {@code CompressionCodecResolver} in these cases.</p>
     * <p>However, if you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you must implement
     * your own {@link CompressionCodecResolver} and specify that via this method and also when
     * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} JWTs.</p>
     *
     * @param compressionCodecResolver the compression codec resolver used to decompress the JWT body.
     * @return the parser for method chaining.
     * @since 0.6.0
     * @deprecated see {@link JwtParserBuilder#setCompressionCodecResolver(CompressionCodecResolver)}.
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
     * @deprecated see {@link JwtParserBuilder#deserializeJsonWith(Deserializer)}.
     * To construct a JwtParser use the corresponding builder via {@link Jwts#parserBuilder()}. This will construct an
     * immutable JwtParser.
     * <p><b>NOTE: this method will be removed before version 1.0</b>
     */
    @Deprecated
    JwtParser deserializeJsonWith(Deserializer<Map<String,?>> deserializer);

    /**
     * Returns {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     * <p>
     * <p>Note that if you are reasonably sure that the token is signed, it is more efficient to attempt to
     * parse the token (and catching exceptions if necessary) instead of calling this method first before parsing.</p>
     *
     * @param jwt the compact serialized JWT to check
     * @return {@code true} if the specified JWT compact string represents a signed JWT (aka a 'JWS'), {@code false}
     * otherwise.
     */
    boolean isSigned(String jwt);

    /**
     * @deprecated
     *      Has been renamed to {@link #parseSignedOrUnsigned(String)}.<br/>
     *      The name of this method is misleading and has lead to incorrect and unsafe usage, because it allows both
     *      signed <b>and unsigned</b> tokens. It has been renamed to {@link #parseSignedOrUnsigned(String)}; that
     *      method behaves exactly identical to this one.
     */
    @Deprecated
    Jwt parse(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the parser's configuration state and
     * returns the resulting JWT or JWS instance. This method allows both signed <b>and unsigned</b> tokens,
     * it should only be used when it is unknown in advance wether a token will be signed or which format its
     * payload will have. If the exact format of the token is known beforehand, one of the specific parsing methods
     * should be used instead.
     *
     * <p>Depending on whether the token is signed or not, either a {@link Jws} (for signed tokens) or a {@link Jwt}
     * which is not an instance of {@code Jws} (for unsigned tokens) is returned. Because it may be cumbersome to
     * determine if the result is a JWT or JWS, or if the body/payload is a Claims or String, the
     * {@link #parse(String, JwtHandler)} method allows for a type-safe callback approach that may help reduce
     * the amount of required code.</p>
     *
     * @param jwt the compact serialized JWT to parse
     * @return the specified compact serialized JWT string based on the parser's configuration state.
     * @throws MalformedJwtException    if the specified JWT was incorrectly constructed (and therefore invalid).
     *                                  Invalid
     *                                  JWTs should not be trusted and should be discarded.
     * @throws SignatureException       if a JWS signature was discovered, but could not be verified.  JWTs that fail
     *                                  signature validation should not be trusted and should be discarded.
     * @throws ExpiredJwtException      if the specified JWT is a Claims JWT and the Claims has an expiration time
     *                                  before the time this method is invoked.
     * @throws IllegalArgumentException if the specified string is {@code null} or empty or only whitespace.
     * @see #parse(String, JwtHandler)
     * @see #parsePlaintextUnsignedJwt(String)
     * @see #parseClaimsUnsignedJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     */
    Jwt parseSignedOrUnsigned(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified compact serialized JWT string based on the parser's configuration state and
     * invokes the respective method of the specified {@code handler} with the resulting JWT or JWS instance,
     * depending on whether the token is signed or not, and whether its payload consists of JSON data.
     * <p>
     * <p>If you are confident of the format of the JWT before parsing, you can create an anonymous subclass using the
     * {@link io.jsonwebtoken.JwtHandlerAdapter JwtHandlerAdapter} and override only the methods you know are relevant
     * for your use case(s), for example:</p>
     * <p>
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
     * <p>
     * <p>If the exact format of the token is known beforehand, i.e. whether the token is signed and whether its
     * payload consists of JSON data, one of the specific {@code JwtParser} parsing methods should be used instead.
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
     * @see #parsePlaintextUnsignedJwtString)
     * @see #parseClaimsUnsignedJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parseSignedOrUnsigned(String)
     * @since 0.2
     */
    <T> T parse(String jwt, JwtHandler<T> handler)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * @since 0.2
     * @deprecated
     *      Has been renamed to {@link #parsePlaintextUnsignedJwt(String)}.<br/>
     *      The name of this method is misleading and can lead to incorrect and unsafe usage. It has been renamed to
     *      {@link #parsePlaintextUnsignedJwt(String)}; that method behaves exactly identical to this one.
     */
    @Deprecated
    Jwt<Header, String> parsePlaintextJwt(String plaintextJwt)
        throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified <b>unsigned</b> compact serialized JWT string with non-JSON payload based on the parser's
     * configuration state and returns the resulting JWT instance.
     * <p>
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unsigned plaintext JWT. An unsigned plaintext JWT has a String (non-JSON) body payload and it is not
     * cryptographically signed.</p>
     * <p>
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
     * @see #parseClaimsUnsignedJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parseSignedOrUnsigned(String)
     * @since 0.2
     */
    Jwt<Header, String> parsePlaintextUnsignedJwt(String plaintextJwt)
        throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * @since 0.2
     * @deprecated
     *      Has been renamed to {@link #parseClaimsUnsignedJwt(String)}.<br/>
     *      The name of this method is misleading and can lead to incorrect and unsafe usage. It has been renamed to
     *      {@link #parseClaimsUnsignedJwt(String)}; that method behaves exactly identical to this one.
     */
    @Deprecated
    Jwt<Header, Claims> parseClaimsJwt(String claimsJwt)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified <b>unsigned</b> compact serialized JWT string with JSON payload based on the parser's
     * configuration state and returns the resulting JWT instance.
     * <p>
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects an
     * unsigned Claims JWT. An unsigned Claims JWT has a {@link Claims} body and it is not cryptographically
     * signed.</p>
     * <p>
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
     * @see #parsePlaintextUnsignedJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parseSignedOrUnsigned(String)
     * @since 0.2
     */
    Jwt<Header, Claims> parseClaimsUnsignedJwt(String claimsJwt)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified signed compact serialized JWS string with non-JSON payload based on the parser's 
     * configuration state and returns the resulting JWS instance.
     * <p>
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * plaintext JWS. A plaintext JWS is a JWT with a String (non-JSON) body (payload) that has been
     * cryptographically signed.</p>
     * <p>
     * <p><b>If the compact string presented does not reflect a plaintext JWS, an {@link UnsupportedJwtException}
     * will be thrown.</b></p>
     *
     * @param plaintextJws a compact serialized JWS string.
     * @return the {@link Jws Jws} instance that reflects the specified compact JWS string.
     * @throws UnsupportedJwtException  if the {@code plaintextJws} argument does not represent an plaintext JWS
     * @throws MalformedJwtException    if the {@code plaintextJws} string is not a valid JWS
     * @throws SignatureException       if the {@code plaintextJws} JWS signature validation fails
     * @throws IllegalArgumentException if the {@code plaintextJws} string is {@code null} or empty or only whitespace
     * @see #parsePlaintextUnsignedJwt(String)
     * @see #parseClaimsUnsignedJwt(String)
     * @see #parseClaimsJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parseSignedOrUnsigned(String)
     * @since 0.2
     */
    Jws<String> parsePlaintextJws(String plaintextJws)
        throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;

    /**
     * Parses the specified signed compact serialized JWS string with JSON payload based on the parser's configuration
     * state and returns the resulting JWS instance.
     * <p>
     * <p>This is a convenience method that is usable if you are confident that the compact string argument reflects a
     * Claims JWS. A Claims JWS is a JWT with a {@link Claims} body that has been cryptographically signed.</p>
     * <p>
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
     * @see #parsePlaintextUnsignedJwt(String)
     * @see #parseClaimsUnsignedJwt(String)
     * @see #parsePlaintextJws(String)
     * @see #parse(String, JwtHandler)
     * @see #parseSignedOrUnsigned(String)
     * @since 0.2
     */
    Jws<Claims> parseClaimsJws(String claimsJws)
        throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;
}

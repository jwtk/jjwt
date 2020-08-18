/*
 * Copyright (C) 2019 jsonwebtoken.io
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
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;

import java.security.Key;
import java.security.Provider;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * A builder to construct a {@link JwtParser}. Example usage:
 * <pre>{@code
 *     Jwts.parserBuilder()
 *         .setSigningKey(...)
 *         .requireIssuer("https://issuer.example.com")
 *         .build()
 *         .parse(jwtString)
 * }</pre>
 * @since 0.11.0
 */
public interface JwtParserBuilder {

    /**
     * Sets the JCA Provider to use during cryptographic signature and decryption operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic signature and decryption operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder setProvider(Provider provider);

    /**
     * Ensures that the specified {@code jti} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param id {@code jti} value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireId(String id);

    /**
     * Ensures that the specified {@code sub} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param subject the required subject value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireSubject(String subject);

    /**
     * Ensures that the specified {@code aud} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param audience the required audience value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireAudience(String audience);

    /**
     * Ensures that the specified {@code iss} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param issuer the required issuer value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireIssuer(String issuer);

    /**
     * Ensures that the specified {@code iat} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param issuedAt the required issuedAt value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireIssuedAt(Date issuedAt);

    /**
     * Ensures that the specified {@code exp} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param expiration the required expiration value
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireExpiration(Date expiration);

    /**
     * Ensures that the specified {@code nbf} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param notBefore the required not before {@code nbf} value.
     * @return the parser builder for method chaining
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder requireNotBefore(Date notBefore);

    /**
     * Ensures that the specified {@code claimName} exists in the parsed JWT.  If missing or if the parsed
     * value does not equal the specified value, an exception will be thrown indicating that the
     * JWT is invalid and may not be used.
     *
     * @param claimName the name of the claim to require
     * @param value the value the claim value must equal
     * @return the parser builder for method chaining.
     * @see MissingClaimException
     * @see IncorrectClaimException
     */
    JwtParserBuilder require(String claimName, Object value);

    /**
     * Sets the {@link Clock} that determines the timestamp to use when validating the parsed JWT.
     * The parser uses a default Clock implementation that simply returns {@code new Date()} when called.
     *
     * @param clock a {@code Clock} object to return the timestamp to use when validating the parsed JWT.
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder setClock(Clock clock);

    /**
     * Sets the amount of clock skew in seconds to tolerate when verifying the local time against the {@code exp}
     * and {@code nbf} claims.
     *
     * @param seconds the number of seconds to tolerate for clock skew when verifying {@code exp} or {@code nbf} claims.
     * @return the parser builder for method chaining.
     * @throws IllegalArgumentException if {@code seconds} is a value greater than {@code Long.MAX_VALUE / 1000} as
     * any such value would cause numeric overflow when multiplying by 1000 to obtain a millisecond value.
     */
    JwtParserBuilder setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException;

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
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder setSigningKey(byte[] key);

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
     * @return the parser builder for method chaining.
     * @deprecated as of 0.10.0.
     */
    @Deprecated
    JwtParserBuilder setSigningKey(String base64EncodedSecretKey);

    /**
     * Sets the signature verification key used to verify all encountered JWS signatures. If the encountered JWT
     * string is not a JWS (e.g. unsigned or a JWE), this key is not used.
     * <p/>
     * <p>This is a convenience method to use in specific circumstances: when the parser will only ever encounter
     * JWSs with signatures that can always be verified by a single key.  This also implies that this key
     * <em>MUST</em> be a valid key for the signature algorithm ({@code alg} header) used for the JWS.</p>
     * <p/>
     * <p>If there is any chance that the parser will encounter JWSs
     * that need different signature verification keys based on the JWS being parsed, it is strongly
     * recommended to configure your own {@link Locator Locator<?,Key>} via the
     * {@link #setKeyLocator(Locator) setKeyLocator} method instead of using this one.</p>
     * <p/>
     * <p>Calling this method overrides any previously set signature verification key.</p>
     *
     * @param key the algorithm-specific signature verification key to use to verify all encountered JWS digital
     *            signatures.
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder setSigningKey(Key key);

    /**
     * Sets the decryption key to be used to decrypt all encountered JWEs.  If the encountered JWT string is not a
     * JWE (e.g. a JWS), this key is not used.
     * <p/>
     * <p>This is a convenience method to use in specific circumstances: when the parser will only ever encounter
     * JWEs that can always be decrypted by a single key.  This also implies that this key <em>MUST</em> be a valid
     * key for both the key management algorithm ({@code alg} header) and the content encryption algorithm
     * ({@code enc} header) used for the JWE.</p>
     * <p/>
     * <p>If there is any chance that the parser will encounter JWEs
     * that need different decryption keys based on the JWE being parsed, it is strongly recommended to configure
     * your own {@link Locator Locator<?,Key>} via the {@link #setKeyLocator(Locator) setKeyLocator} method instead of
     * using this one.</p>
     * <p/>
     * <p>Calling this method overrides any previously set decryption key.</p>
     * @param key the algorithm-specific decryption key to use to decrypt all encountered JWEs.
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder decryptWith(Key key);

    /**
     * Sets the {@link Locator} used to acquire any signature verification or decryption key needed during parsing.
     * <ul>
     *     <li>If the parsed String is a JWS, the {@code Locator} will be called to find the appropriate key
     *     necessary to verify the JWS signature.</li>
     *     <li>If the parsed String is a JWE, it will be called to find the appropriate decryption key.</li>
     * </ul>
     * <p>
     * <p>Specifying a key {@code Locator} is necessary when the signing or decryption key is not already known before
     * parsing the JWT and the JWT header must be inspected first to determine how to
     * look up the verification or decryption key.  Once returned by the locator, the JwtParser will then either
     * verify the JWS signature or decrypt the JWE payload with the returned key.  For example:</p>
     * <p>
     * <pre>
     * Jws&lt;Claims&gt; jws = Jwts.parser().setKeyLocator(new Locator&lt;Header,Key&gt;() {
     *         &#64;Override
     *         public Key locate(Header header) {
     *             if (header instanceof JwsHeader) {
     *                 return getSignatureVerificationKey((JwsHeader)header); // implement me
     *             } else {
     *                 return getDecryptionKey((JweHeader)header); // implement me
     *             }
     *         }})
     *     .parseClaimsJws(compact);
     * </pre>
     * <p>
     * <p>A Key {@code Locator} is invoked once during parsing before performing decryption or signature verification.</p>
     *
     * @param keyLocator the locator used to retrieve decryption or signature verification keys.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder setKeyLocator(Locator<? extends Header<?>, Key> keyLocator);

    /**
     * <h4>Deprecation Notice</h4>
     * <p>This method has been deprecated as of JJWT version JJWT_RELEASE_VERSION because it only supports key location
     * for JWSs (signed JWTs) instead of both signed (JWS) and encrypted (JWE) scenarios.  Use the
     * {@link #setKeyLocator(Locator) setKeyLocator} method instead to ensure a locator that can work for both JWS and
     * JWE inputs.  This method will be removed for the 1.0 release.</p>
     * <h4>Previous Documentation</h4>
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
     * @deprecated since JJWT_RELEASE_VERSION
     * @param signingKeyResolver the signing key resolver used to retrieve the signing key.
     * @return the parser builder for method chaining.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    JwtParserBuilder addEncryptionAlgorithms(Collection<AeadAlgorithm> encAlgs);

    JwtParserBuilder addSignatureAlgorithms(Collection<SignatureAlgorithm<?,?>> sigAlgs);

    JwtParserBuilder addKeyAlgorithms(Collection<KeyAlgorithm<?,?>> keyAlgs);

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
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver);

    /**
     * Perform Base64Url decoding with the specified Decoder
     *
     * <p>JJWT uses a spec-compliant decoder that works on all supported JDK versions, but you may call this method
     * to specify a different decoder if you desire.</p>
     *
     * @param base64UrlDecoder the decoder to use when Base64Url-decoding
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder);

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
     * @return the builder for method chaining.
     */
    JwtParserBuilder deserializeJsonWith(Deserializer<Map<String,?>> deserializer);

    /**
     * Returns an immutable/thread-safe {@link JwtParser} created from the configuration from this JwtParserBuilder.
     * @return an immutable/thread-safe JwtParser created from the configuration from this JwtParserBuilder.
     */
    JwtParser build();
}

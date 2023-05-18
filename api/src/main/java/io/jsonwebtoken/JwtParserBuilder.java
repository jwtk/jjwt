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
import io.jsonwebtoken.lang.Builder;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.StandardKeyAlgorithms;
import io.jsonwebtoken.security.StandardSecureDigestAlgorithms;

import java.security.Key;
import java.security.Provider;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * A builder to construct a {@link JwtParser}. Example usage:
 * <pre>{@code
 *     Jwts.parserBuilder()
 *         .requireIssuer("https://issuer.example.com")
 *         .verifyWith(...)
 *         .build()
 *         .parse(jwtString)
 * }</pre>
 *
 * @since 0.11.0
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface JwtParserBuilder extends Builder<JwtParser> {

    /**
     * Enables parsing of Unsecured JWSs (JWTs with an 'alg' (Algorithm) header value of
     * 'none'). <b>Be careful when calling this method - one should fully understand
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * before enabling this feature.</b>
     * <p>If this method is not called, Unsecured JWSs are disabled by default as mandated by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section
     * 3.6</a>.</p>
     *
     * @return the builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">Using the Algorithm &quot;none&quot;</a>
     * @see StandardSecureDigestAlgorithms#NONE
     * @see #enableUnsecuredDecompression()
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder enableUnsecuredJws();

    /**
     * If {@link #enableUnsecuredJws() enabledUnsecuredJws} is enabled, calling this method additionally enables
     * payload decompression of Unsecured JWSs (JWTs with an 'alg' (Algorithm) header value of 'none') that also have
     * a 'zip' (Compression) header. This behavior is disabled by default because using compression
     * algorithms with data from unverified (unauthenticated) parties can be susceptible to Denial of Service attacks
     * and other data integrity problems as described in
     * <a href="https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf">In the
     * Compression Hornet’s Nest: A Security Study of Data Compression in Network Services</a>.
     *
     * <p>Because this behavior is only relevant if {@link #enableUnsecuredJws() enabledUnsecuredJws} is specified,
     * calling this method without also calling {@code enableUnsecuredJws()} will result in a build exception, as the
     * incongruent state could reflect a misunderstanding of both behaviors which should be remedied by the
     * application developer.</p>
     *
     * <b>As is the case for {@link #enableUnsecuredJws()}, be careful when calling this method - one should fully
     * understand
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * before enabling this feature.</b>
     *
     * @return the builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * @see <a href="https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf">In the
     * Compression Hornet’s Nest: A Security Study of Data Compression in Network Services</a>
     * @see StandardSecureDigestAlgorithms#NONE
     * @see #enableUnsecuredJws()
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder enableUnsecuredDecompression();

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
     * @param id the required value of the {@code jti} header parameter.
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
     * @param subject the required value of the {@code sub} header parameter.
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
     * @param audience the required value of the {@code aud} header parameter.
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
     * @param issuer the required value of the {@code iss} header parameter.
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
     * @param issuedAt the required value of the {@code iat} header parameter.
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
     * @param expiration the required value of the {@code exp} header parameter.
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
     * @param notBefore the required value of the {@code npf} header parameter.
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
     * @param claimName the name of a claim that must exist
     * @param value     the required value of the specified {@code claimName}
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
     *                                  any such value would cause numeric overflow when multiplying by 1000 to obtain
     *                                  a millisecond value.
     */
    JwtParserBuilder setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException;

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>This method has been deprecated since JJWT_RELEASE_VERSION and will be removed before 1.0.  It was not
     * readily obvious to many JJWT users that this method was for bytes that pertained <em>only</em> to HMAC
     * {@code SecretKey}s, and could be confused with keys of other types.  It is better to obtain a type-safe
     * {@link Key} instance and call the {@link #verifyWith(Key)} instead.</p>
     *
     * <p>Previous Documentation</p>
     *
     * <p>Sets the signing key used to verify any discovered JWS digital signature.  If the specified JWT string is not
     * a JWS (no signature), this key is not used.</p>
     *
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * <p>This method overwrites any previously set key.</p>
     *
     * @param key the algorithm-specific signature verification key used to validate any discovered JWS digital
     *            signature.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #verifyWith(Key)} for type safety and name congruence
     * with the {@link #decryptWith(Key)} method.
     */
    @Deprecated
    JwtParserBuilder setSigningKey(byte[] key);

    /**
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
     * <p>Finally, please use the {@link #verifyWith(Key)} method instead, as this method (and likely
     * {@link #setSigningKey(byte[])}) will be removed before the 1.0.0 release.</p>
     *
     * <p><b>Previous JavaDoc</b></p>
     *
     * <p>This is a convenience method that equates to the following:</p>
     *
     * <blockquote><pre>
     * byte[] bytes = Decoders.{@link io.jsonwebtoken.io.Decoders#BASE64 BASE64}.decode(base64EncodedSecretKey);
     * Key key = Keys.{@link io.jsonwebtoken.security.Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor}(bytes);
     * return {@link #verifyWith(Key) verifyWith}(key);</pre></blockquote>
     *
     * @param base64EncodedSecretKey BASE64-encoded HMAC-SHA key bytes used to create a Key which will be used to
     *                               verify all encountered JWS digital signatures.
     * @return the parser builder for method chaining.
     * @deprecated in favor of {@link #verifyWith(Key)} as explained in the above <b>Deprecation Notice</b>,
     * and will be removed in 1.0.0.
     */
    @Deprecated
    JwtParserBuilder setSigningKey(String base64EncodedSecretKey);

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>This method is being renamed to accurately reflect its purpose - the key is not technically a signing key,
     * it is a signature verification key, and the two concepts can be different, especially with asymmetric key
     * cryptography.  The method has been deprecated since JJWT_RELEASE_VERSION in favor of
     * {@link #verifyWith(Key)} for type safety, to reflect accurate naming of the concept, and for name congruence
     * with the {@link #decryptWith(Key)} method.</p>
     *
     * <p>This method merely delegates directly to {@link #verifyWith(Key)}.</p>
     *
     * @param key the algorithm-specific signature verification key to use to verify all encountered JWS digital
     *            signatures.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #verifyWith(Key)} for naming congruence with the
     * {@link #decryptWith(Key)} method.
     */
    @Deprecated
    JwtParserBuilder setSigningKey(Key key);

    /**
     * Sets the signature verification key used to verify all encountered JWS signatures. If the encountered JWT
     * string is not a JWS (e.g. unsigned or a JWE), this key is not used.
     *
     * <p>This is a convenience method to use in a specific scenario: when the parser will only ever encounter
     * JWSs with signatures that can always be verified by a single key.  This also implies that this key
     * <em>MUST</em> be a valid key for the signature algorithm ({@code alg} header) used for the JWS.</p>
     *
     * <p>If there is any chance that the parser will encounter JWSs
     * that need different signature verification keys based on the JWS being parsed, or JWEs, it is strongly
     * recommended to configure your own {@link Locator} via the
     * {@link #setKeyLocator(Locator) setKeyLocator} method instead of using this one.</p>
     *
     * <p>Calling this method overrides any previously set signature verification key.</p>
     *
     * @param key the signature verification key to use to verify all encountered JWS digital signatures.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder verifyWith(Key key);

    /**
     * Sets the decryption key to be used to decrypt all encountered JWEs.  If the encountered JWT string is not a
     * JWE (e.g. a JWS), this key is not used.
     *
     * <p>This is a convenience method to use in specific circumstances: when the parser will only ever encounter
     * JWEs that can always be decrypted by a single key.  This also implies that this key <em>MUST</em> be a valid
     * key for both the key management algorithm ({@code alg} header) and the content encryption algorithm
     * ({@code enc} header) used for the JWE.</p>
     *
     * <p>If there is any chance that the parser will encounter JWEs that need different decryption keys based on the
     * JWE being parsed, or JWSs, it is strongly recommended to configure
     * your own {@link Locator Locator} via the {@link #setKeyLocator(Locator) setKeyLocator} method instead of
     * using this one.</p>
     *
     * <p>Calling this method overrides any previously set decryption key.</p>
     *
     * @param key the algorithm-specific decryption key to use to decrypt all encountered JWEs.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder decryptWith(Key key);

    /**
     * Sets the {@link Locator} used to acquire any signature verification or decryption key needed during parsing.
     * <ul>
     *     <li>If the parsed String is a JWS, the {@code Locator} will be called to find the appropriate key
     *     necessary to verify the JWS signature.</li>
     *     <li>If the parsed String is a JWE, it will be called to find the appropriate decryption key.</li>
     * </ul>
     *
     * <p>Specifying a key {@code Locator} is necessary when the signing or decryption key is not already known before
     * parsing the JWT and the JWT header must be inspected first to determine how to
     * look up the verification or decryption key.  Once returned by the locator, the JwtParser will then either
     * verify the JWS signature or decrypt the JWE payload with the returned key.  For example:</p>
     *
     * <pre>
     * Jws&lt;Claims&gt; jws = Jwts.parserBuilder().setKeyLocator(new Locator&lt;Key&gt;() {
     *         &#64;Override
     *         public Key locate(Header&lt;?&gt; header) {
     *             if (header instanceof JwsHeader) {
     *                 return getSignatureVerificationKey((JwsHeader)header); // implement me
     *             } else {
     *                 return getDecryptionKey((JweHeader)header); // implement me
     *             }
     *         }})
     *     .build()
     *     .parseClaimsJws(compact);
     * </pre>
     *
     * <p>A Key {@code Locator} is invoked once during parsing before performing decryption or signature verification.</p>
     *
     * @param keyLocator the locator used to retrieve decryption or signature verification keys.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder setKeyLocator(Locator<Key> keyLocator);

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>This method has been deprecated as of JJWT version JJWT_RELEASE_VERSION because it only supports key location
     * for JWSs (signed JWTs) instead of both signed (JWS) and encrypted (JWE) scenarios.  Use the
     * {@link #setKeyLocator(Locator) setKeyLocator} method instead to ensure a locator that can work for both JWS and
     * JWE inputs.  This method will be removed for the 1.0 release.</p>
     *
     * <p><b>Previous Documentation</b></p>
     *
     * <p>Sets the {@link SigningKeyResolver} used to acquire the <code>signing key</code> that should be used to verify
     * a JWS's signature.  If the parsed String is not a JWS (no signature), this resolver is not used.</p>
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
     * @param signingKeyResolver the signing key resolver used to retrieve the signing key.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #setKeyLocator(Locator)}
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    /**
     * Adds the specified compression codecs to the parser's total set of supported compression codecs,
     * overwriting any previously-added compression codecs with the same {@link CompressionCodec#getId() id}s. If the
     * parser encounters a JWT {@code zip} header value that matches a compression codec's
     * {@link CompressionCodec#getId() CompressionCodec.getId()}, that codec will be used for decompression.
     *
     * <p>There may be only one registered {@code CompressionCodec} per {@code id}, and the {@code codecs}
     * collection is added in iteration order; if a duplicate id is found when iterating the {@code codecs}
     * collection, the later element will evict any previously-added algorithm with the same {@code id}.</p>
     *
     * <p>Finally, {@link CompressionCodecs#DEFLATE} and {@link CompressionCodecs#GZIP} are added last,
     * <em>after</em> those in the {@code codecs} collection, to ensure that JWA standard algorithms cannot be
     * accidentally replaced.</p>
     *
     * <p>This method is a simpler alternative than creating and registering a custom locator via the
     * {@link #setCompressionCodecLocator(Locator)} method.</p>
     *
     * @param codecs collection of compression codecs to add to the parser's total set of supported compression codecs.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addCompressionCodecs(Collection<? extends CompressionCodec> codecs);

    /**
     * Adds the specified AEAD encryption algorithms to the parser's total set of supported encryption algorithms,
     * overwriting any previously-added algorithms with the same {@link AeadAlgorithm#getId() id}s.
     *
     * <p>There may be only one registered {@code AeadAlgorithm} per algorithm {@code id}, and the {@code encAlgs}
     * collection is added in iteration order; if a duplicate id is found when iterating the {@code encAlgs}
     * collection, the later element will evict any previously-added algorithm with the same {@code id}.</p>
     *
     * <p>Finally, the {@link Jwts#ENC JWA standard encryption algorithms} are added last,
     * <em>after</em> those in the {@code encAlgs} collection, to ensure that JWA standard algorithms cannot be
     * accidentally replaced.</p>
     *
     * @param encAlgs collection of AEAD encryption algorithms to add to the parser's total set of supported
     *                encryption algorithms.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addEncryptionAlgorithms(Collection<? extends AeadAlgorithm> encAlgs);

    /**
     * Adds the specified signature algorithms to the parser's total set of supported signature algorithms,
     * overwriting any previously-added algorithms with the same
     * {@link Identifiable#getId() id}s.
     *
     * <p>There may be only one registered {@code SecureDigestAlgorithm} per algorithm {@code id}, and the
     * {@code sigAlgs} collection is added in iteration order; if a duplicate id is found when iterating the
     * {@code sigAlgs} collection, the later element will evict any previously-added algorithm with the same
     * {@code id}.</p>
     *
     * <p>Finally, the {@link Jwts#SIG JWA standard signature and MAC algorithms} are
     * added last, <em>after</em> those in the {@code sigAlgs} collection, to ensure that JWA standard algorithms
     * cannot be accidentally replaced.</p>
     *
     * @param sigAlgs collection of signing algorithms to add to the parser's total set of supported signature
     *                algorithms.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addSignatureAlgorithms(Collection<? extends SecureDigestAlgorithm<?, ?>> sigAlgs);

    /**
     * Adds the specified key management algorithms to the parser's total set of supported key algorithms,
     * overwriting any previously-added algorithms with the same {@link KeyAlgorithm#getId() id}s.
     *
     * <p>There may be only one registered {@code KeyAlgorithm} per algorithm {@code id}, and the {@code keyAlgs}
     * collection is added in iteration order; if a duplicate id is found when iterating the {@code keyAlgs}
     * collection, the later element will evict any previously-added algorithm with the same {@code id}.</p>
     *
     * <p>Finally, the {@link StandardKeyAlgorithms#values() JWA standard key management algorithms}
     * are added last, <em>after</em> those in the {@code keyAlgs} collection, to ensure that JWA standard algorithms
     * cannot be accidentally replaced.</p>
     *
     * @param keyAlgs collection of key management algorithms to add to the parser's total set of supported key
     *                management algorithms.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addKeyAlgorithms(Collection<? extends KeyAlgorithm<?, ?>> keyAlgs);

    /**
     * Sets the {@link CompressionCodecResolver} used to acquire the {@link CompressionCodec} that should be used to
     * decompress the JWT body. If the parsed JWT is not compressed, this resolver is not used.
     *
     * <p><b>NOTE:</b> Compression is not defined by the JWS Specification - only the JWE Specification - and it is
     * not expected that other libraries (including JJWT versions &lt; 0.6.0) are able to consume a compressed JWS
     * body correctly.  This method is only useful if the compact JWS was compressed with JJWT &gt;= 0.6.0 or
     * another library that you know implements the same behavior.</p>
     *
     * <p><b>Default Support</b></p>
     *
     * <p>JJWT's default {@link JwtParser} implementation supports both the
     * {@link CompressionCodecs#DEFLATE DEFLATE}
     * and {@link CompressionCodecs#GZIP GZIP} algorithms by default - you do not need to
     * specify a {@code CompressionCodecResolver} in these cases.</p>
     *
     * <p>However, if you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, you must
     * implement your own {@link CompressionCodecResolver} and specify that via this method and also when
     * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} JWTs.</p>
     *
     * @param compressionCodecResolver the compression codec resolver used to decompress the JWT body.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #setCompressionCodecLocator(Locator)} to use the
     * congruent {@code Locator} concept used elsewhere (such as {@link #setKeyLocator(Locator)}).
     */
    @Deprecated
    JwtParserBuilder setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver);

    /**
     * Sets the {@link CompressionCodec} {@code Locator} used to acquire the {@code CompressionCodec} that should be
     * used to decompress the JWT body.
     *
     * <p><b>NOTE:</b> Compression is not defined by the JWS Specification - only the JWE Specification - and it is
     * not expected that other libraries (including JJWT versions &lt; 0.6.0) are able to consume a compressed JWS
     * body correctly.  This method is only useful if the compact JWS was compressed with JJWT &gt;= 0.6.0 or
     * another library that you know implements the same behavior.</p>
     *
     * <p><b>Simple Registration</b></p>
     *
     * <p>If a CompressionCodec can be resolved in the JWT Header via a simple {@code zip} header value lookup, it is
     * recommended to call the {@link #addCompressionCodecs(Collection)} method instead of this one.  That method
     * will add the codec to the total set of supported codecs and lookup will achieved by matching the
     * {@link CompressionCodec#getId() CompressionCodec.getId()} against the {@code zip} header value automatically.</p>
     *
     * <p>You only need to call this method with a custom locator if compression codec lookup cannot be based on the
     * {@code zip} header value.</p>
     *
     * <p><b>Default Support</b></p>
     *
     * <p>JJWT's default {@link JwtParser} implementation supports both the
     * {@link CompressionCodecs#DEFLATE DEFLATE}
     * and {@link CompressionCodecs#GZIP GZIP} algorithms by default - you do not need to
     * specify a {@code CompressionCodec} {@link Locator} in these cases.</p>
     *
     * <p>However, if you want to use a compression algorithm other than {@code DEF} or {@code GZIP}, and
     * {@link #addCompressionCodecs(Collection)} is not sufficient, you must
     * implement your own {@code CompressionCodec} {@link Locator} and specify that via this method and also when
     * {@link io.jsonwebtoken.JwtBuilder#compressWith(CompressionCodec) building} JWTs.</p>
     *
     * @param locator the compression codec locator used to decompress the JWT body.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder setCompressionCodecLocator(Locator<CompressionCodec> locator);

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
    JwtParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer);

    /**
     * Returns an immutable/thread-safe {@link JwtParser} created from the configuration from this JwtParserBuilder.
     *
     * @return an immutable/thread-safe JwtParser created from the configuration from this JwtParserBuilder.
     */
    JwtParser build();
}

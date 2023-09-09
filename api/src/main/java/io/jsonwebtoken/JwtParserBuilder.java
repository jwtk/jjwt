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

import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Builder;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * A builder to construct a {@link JwtParser}. Example usage:
 * <pre>{@code
 *     Jwts.parser()
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
     * Enables parsing of Unsecured JWTs (JWTs with an 'alg' (Algorithm) header value of
     * 'none' or missing the 'alg' header entirely). <b>Be careful when calling this method - one should fully understand
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * before enabling this feature.</b>
     * <p>If this method is not called, Unsecured JWTs are disabled by default as mandated by
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">RFC 7518, Section
     * 3.6</a>.</p>
     *
     * @return the builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6">Using the Algorithm &quot;none&quot;</a>
     * @see Jwts.SIG#NONE
     * @see #enableUnsecuredDecompression()
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder enableUnsecured();

    /**
     * If {@link #enableUnsecured() enabledUnsecuredJws} is enabled, calling this method additionally enables
     * payload decompression of Unsecured JWTs (JWTs with an 'alg' (Algorithm) header value of 'none') that also have
     * a 'zip' (Compression) header. This behavior is disabled by default because using compression
     * algorithms with data from unverified (unauthenticated) parties can be susceptible to Denial of Service attacks
     * and other data integrity problems as described in
     * <a href="https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf">In the
     * Compression Hornet’s Nest: A Security Study of Data Compression in Network Services</a>.
     *
     * <p>Because this behavior is only relevant if {@link #enableUnsecured() enabledUnsecured} is specified,
     * calling this method without also calling {@code enableUnsecured()} will result in a build exception, as the
     * incongruent state could reflect a misunderstanding of both behaviors which should be remedied by the
     * application developer.</p>
     *
     * <b>As is the case for {@link #enableUnsecured()}, be careful when calling this method - one should fully
     * understand
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * before enabling this feature.</b>
     *
     * @return the builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-8.5">Unsecured JWS Security Considerations</a>
     * @see <a href="https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf">In the
     * Compression Hornet’s Nest: A Security Study of Data Compression in Network Services</a>
     * @see Jwts.SIG#NONE
     * @see #enableUnsecured()
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder enableUnsecuredDecompression();

    /**
     * Sets the JCA Provider to use during cryptographic signature and key decryption operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic signature and decryption operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder provider(Provider provider);

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
     * value does not contain the specified value, an exception will be thrown indicating that the
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
     * @deprecated since JJWT_RELEASE_VERSION for the more modern builder-style named {@link #clock(Clock)} method.
     * This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    JwtParserBuilder setClock(Clock clock);

    /**
     * Sets the {@link Clock} that determines the timestamp to use when validating the parsed JWT.
     * The parser uses a default Clock implementation that simply returns {@code new Date()} when called.
     *
     * @param clock a {@code Clock} object to return the timestamp to use when validating the parsed JWT.
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder clock(Clock clock);

    /**
     * Sets the amount of clock skew in seconds to tolerate when verifying the local time against the {@code exp}
     * and {@code nbf} claims.
     *
     * @param seconds the number of seconds to tolerate for clock skew when verifying {@code exp} or {@code nbf} claims.
     * @return the parser builder for method chaining.
     * @throws IllegalArgumentException if {@code seconds} is a value greater than {@code Long.MAX_VALUE / 1000} as
     *                                  any such value would cause numeric overflow when multiplying by 1000 to obtain
     *                                  a millisecond value.
     * @deprecated since JJWT_RELEASE_VERSION in favor of the shorter and more modern builder-style named
     * {@link #clockSkewSeconds(long)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    JwtParserBuilder setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException;

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
    JwtParserBuilder clockSkewSeconds(long seconds) throws IllegalArgumentException;

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>This method has been deprecated since JJWT_RELEASE_VERSION and will be removed before 1.0.  It was not
     * readily obvious to many JJWT users that this method was for bytes that pertained <em>only</em> to HMAC
     * {@code SecretKey}s, and could be confused with keys of other types.  It is better to obtain a type-safe
     * {@link SecretKey} instance and call {@link #verifyWith(SecretKey)} instead.</p>
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
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #verifyWith(SecretKey)} for type safety and name
     * congruence with the {@link #decryptWith(SecretKey)} method.
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
     * <p>Finally, please use the {@link #verifyWith(SecretKey)} method instead, as this method (and likely
     * {@link #setSigningKey(byte[])}) will be removed before the 1.0.0 release.</p>
     *
     * <p><b>Previous JavaDoc</b></p>
     *
     * <p>This is a convenience method that equates to the following:</p>
     *
     * <blockquote><pre>
     * byte[] bytes = Decoders.{@link io.jsonwebtoken.io.Decoders#BASE64 BASE64}.decode(base64EncodedSecretKey);
     * Key key = Keys.{@link io.jsonwebtoken.security.Keys#hmacShaKeyFor(byte[]) hmacShaKeyFor}(bytes);
     * return {@link #verifyWith(SecretKey) verifyWith}(key);</pre></blockquote>
     *
     * @param base64EncodedSecretKey BASE64-encoded HMAC-SHA key bytes used to create a Key which will be used to
     *                               verify all encountered JWS digital signatures.
     * @return the parser builder for method chaining.
     * @deprecated in favor of {@link #verifyWith(SecretKey)} as explained in the above <b>Deprecation Notice</b>,
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
     * {@link #verifyWith(SecretKey)} for type safety, to reflect accurate naming of the concept, and for name
     * congruence with the {@link #decryptWith(SecretKey)} method.</p>
     *
     * <p>This method merely delegates directly to {@link #verifyWith(SecretKey)} or {@link #verifyWith(PublicKey)}}.</p>
     *
     * @param key the algorithm-specific signature verification key to use to verify all encountered JWS digital
     *            signatures.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #verifyWith(SecretKey)} for naming congruence with the
     * {@link #decryptWith(SecretKey)} method.
     */
    @Deprecated
    JwtParserBuilder setSigningKey(Key key);

    /**
     * Sets the signature verification SecretKey used to verify all encountered JWS signatures. If the encountered JWT
     * string is not a JWS (e.g. unsigned or a JWE), this key is not used.
     *
     * <p>This is a convenience method to use in a specific scenario: when the parser will only ever encounter
     * JWSs with signatures that can always be verified by a single SecretKey.  This also implies that this key
     * <em>MUST</em> be a valid key for the signature algorithm ({@code alg} header) used for the JWS.</p>
     *
     * <p>If there is any chance that the parser will also encounter JWEs, or JWSs that need different signature
     * verification keys based on the JWS being parsed, it is strongly recommended to configure your own
     * {@link #keyLocator(Locator) keyLocator} instead of calling this method.</p>
     *
     * <p>Calling this method overrides any previously set signature verification key.</p>
     *
     * @param key the signature verification key to use to verify all encountered JWS digital signatures.
     * @return the parser builder for method chaining.
     * @see #verifyWith(PublicKey)
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder verifyWith(SecretKey key);

    /**
     * Sets the signature verification PublicKey used to verify all encountered JWS signatures. If the encountered JWT
     * string is not a JWS (e.g. unsigned or a JWE), this key is not used.
     *
     * <p>This is a convenience method to use in a specific scenario: when the parser will only ever encounter
     * JWSs with signatures that can always be verified by a single PublicKey.  This also implies that this key
     * <em>MUST</em> be a valid key for the signature algorithm ({@code alg} header) used for the JWS.</p>
     *
     * <p>If there is any chance that the parser will also encounter JWEs, or JWSs that need different signature
     * verification keys based on the JWS being parsed, it is strongly recommended to configure your own
     * {@link #keyLocator(Locator) keyLocator} instead of calling this method.</p>
     *
     * <p>Calling this method overrides any previously set signature verification key.</p>
     *
     * @param key the signature verification key to use to verify all encountered JWS digital signatures.
     * @return the parser builder for method chaining.
     * @see #verifyWith(SecretKey)
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder verifyWith(PublicKey key);

    /**
     * Sets the decryption SecretKey used to decrypt all encountered JWEs. If the encountered JWT string is not a
     * JWE (e.g. a JWS), this key is not used.
     *
     * <p>This is a convenience method to use in specific circumstances: when the parser will only ever encounter
     * JWEs that can always be decrypted by a single SecretKey. This also implies that this key <em>MUST</em> be a valid
     * key for both the key management algorithm ({@code alg} header) and the content encryption algorithm
     * ({@code enc} header) used for the JWE.</p>
     *
     * <p>If there is any chance that the parser will also encounter JWSs, or JWEs that need different decryption
     * keys based on the JWE being parsed, it is strongly recommended to configure your own
     * {@link #keyLocator(Locator) keyLocator} instead of calling this method.</p>
     *
     * <p>Calling this method overrides any previously set decryption key.</p>
     *
     * @param key the algorithm-specific decryption key to use to decrypt all encountered JWEs.
     * @return the parser builder for method chaining.
     * @see #decryptWith(PrivateKey)
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder decryptWith(SecretKey key);

    /**
     * Sets the decryption PrivateKey used to decrypt all encountered JWEs. If the encountered JWT string is not a
     * JWE (e.g. a JWS), this key is not used.
     *
     * <p>This is a convenience method to use in specific circumstances: when the parser will only ever encounter JWEs
     * that can always be decrypted by a single PrivateKey. This also implies that this key <em>MUST</em> be a valid
     * key for the JWE's key management algorithm ({@code alg} header).</p>
     *
     * <p>If there is any chance that the parser will also encounter JWSs, or JWEs that need different decryption
     * keys based on the JWE being parsed, it is strongly recommended to configure your own
     * {@link #keyLocator(Locator) keyLocator} instead of calling this method.</p>
     *
     * <p>Calling this method overrides any previously set decryption key.</p>
     *
     * @param key the algorithm-specific decryption key to use to decrypt all encountered JWEs.
     * @return the parser builder for method chaining.
     * @see #decryptWith(SecretKey)
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder decryptWith(PrivateKey key);

    /**
     * Sets the {@link Locator} used to acquire any signature verification or decryption key needed during parsing.
     * <ul>
     *     <li>If the parsed String is a JWS, the {@code Locator} will be called to find the appropriate key
     *     necessary to verify the JWS signature.</li>
     *     <li>If the parsed String is a JWE, it will be called to find the appropriate decryption key.</li>
     * </ul>
     *
     * <p>A key {@code Locator} is necessary when the signature verification or decryption key is not
     * already known before parsing the JWT and the JWT header must be inspected first to determine how to
     * look up the verification or decryption key.  Once returned by the locator, the JwtParser will then either
     * verify the JWS signature or decrypt the JWE payload with the returned key.  For example:</p>
     *
     * <pre>
     * Jws&lt;Claims&gt; jws = Jwts.parser().keyLocator(new Locator&lt;Key&gt;() {
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
     * <p><b>Provider-constrained Keys</b></p>
     *
     * <p>If any verification or decryption key returned from a Key {@code Locator} must be used with a specific
     * security {@link Provider} (such as for PKCS11 or Hardware Security Module (HSM) keys), you must make that
     * Provider available for JWT parsing in one of 3 ways, listed in order of recommendation and simplicity:</p>
     *
     * <ol>
     *     <li><a href="https://docs.oracle.com/en/java/javase/17/security/howtoimplaprovider.html#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33">
     *         Configure the Provider in the JVM</a>, either by modifying the {@code java.security} file or by
     *         registering the Provider dynamically via
     *         {@link java.security.Security#addProvider(Provider) Security.addProvider(Provider)}.  This is the
     *         recommended approach so you do not need to modify code anywhere that may need to parse JWTs.</li>
     *      <li>Specify the {@code Provider} as the {@code JwtParser} default via {@link #provider(Provider)}. This will
     *          ensure the provider is used by default with <em>all</em> located keys unless overridden by a
     *          key-specific Provider. This is only recommended when you are confident that all JWTs encountered by the
     *          parser instance will use keys attributed to the same {@code Provider}, unless overridden by a specific
     *          key.</li>
     *      <li>Associate the {@code Provider} with a specific key so it is used for that key only.  This option
     *          is useful if some located keys require a specific provider, while other located keys can assume a
     *          default provider.</li>
     * </ol>
     *
     * <p>If you need to use option &#35;3, you associate a key for the {@code JwtParser}'s needs by using a
     * key builder before returning the key as the {@code Locator} return value.  For example:</p>
     * <blockquote><pre>
     *     public Key locate(Header&lt;?&gt; header) {
     *         PrivateKey key = findKey(header); // or SecretKey
     *         Provider keySpecificProvider = getKeyProvider(key); // implement me
     *         // associate the key with its required provider:
     *         return Keys.builder(key).provider(keySpecificProvider).build();
     *     }</pre></blockquote>
     *
     * @param keyLocator the locator used to retrieve decryption or signature verification keys.
     * @return the parser builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder keyLocator(Locator<Key> keyLocator);

    /**
     * <p><b>Deprecation Notice</b></p>
     *
     * <p>This method has been deprecated as of JJWT version JJWT_RELEASE_VERSION because it only supports key location
     * for JWSs (signed JWTs) instead of both signed (JWS) and encrypted (JWE) scenarios.  Use the
     * {@link #keyLocator(Locator) keyLocator} method instead to ensure a locator that can work for both JWS and
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
     *     .build().parseClaimsJws(compact);
     * </pre>
     *
     * <p>A {@code SigningKeyResolver} is invoked once during parsing before the signature is verified.</p>
     *
     * @param signingKeyResolver the signing key resolver used to retrieve the signing key.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #keyLocator(Locator)}
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver);

    /**
     * Adds the specified compression algorithms to the parser's total set of supported compression algorithms,
     * replacing any existing ones with identical {@link Identifiable#getId() id}s.
     * If the parser encounters a JWT {@code zip} header value that equals a compression algorithm's
     * {@link Identifiable#getId() id}, that algorithm will be used for decompression.
     *
     * <p>There may be only one registered {@code CompressionAlgorithm} per CaSe-SeNsItIvE {@code id}, and the
     * {@code algs} collection is added in iteration order; if a duplicate id is found when iterating the {@code algs}
     * collection, the later algorithm will evict any existing algorithm with the same {@code id}.</p>
     *
     * <p><b>Standard Algorithms and Overrides</b></p>
     *
     * <p>The {@link Jwts.ZIP} compression algorithms are supported by default and do not need
     * to be added via this method, but beware: <b>any algorithm in the {@code algs} collection with a
     * JWA standard {@link Identifiable#getId() id} will replace the JJWT standard algorithm implementation</b>.
     * This is to allow application developers to favor their own implementations over JJWT's default implementations
     * if necessary (for example, to support legacy or custom behavior).
     *
     * @param algs collection of compression algorithms to add to the parser's total set of supported compression
     *             algorithms, replacing any existing ones with the same exact (CaSe-SeNsItIvE)
     *             {@link CompressionAlgorithm#getId() id}s.
     * @return the builder for method chaining.
     * @see Jwts.ZIP
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addCompressionAlgorithms(Collection<? extends CompressionAlgorithm> algs);

    /**
     * Adds the specified AEAD encryption algorithms to the parser's total set of supported encryption algorithms,
     * replacing any existing algorithms with the same exact (CaSe-SeNsItIvE) {@link AeadAlgorithm#getId() id}s.
     * If the parser encounters a JWT {@code enc} header value that equals an encryption algorithm's
     * {@link Identifiable#getId() id}, that algorithm will be used for decryption.
     *
     * <p>There may be only one registered {@code AeadAlgorithm} per algorithm {@code id}, and the {@code algs}
     * collection is added in iteration order; if a duplicate id is found when iterating the {@code algs}
     * collection, the later algorithm will evict any existing algorithm with the same {@code id}.</p>
     *
     * <p><b>Standard Algorithms and Overrides</b></p>
     *
     * <p>All JWA standard encryption algorithms in {@link Jwts.ENC} are supported by default and do not need
     * to be added via this method, but beware: <b>any algorithm in the {@code algs} collection with a
     * JWA standard {@link Identifiable#getId() id} will replace the JJWT standard algorithm implementation</b>.
     * This is to allow application developers to favor their own implementations over JJWT's default implementations
     * if necessary (for example, to support legacy or custom behavior).
     *
     * @param algs collection of AEAD encryption algorithms to add to the parser's total set of supported
     *             encryption algorithms, replacing any existing algorithms with the same
     *             {@link AeadAlgorithm#getId() id}s.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addEncryptionAlgorithms(Collection<? extends AeadAlgorithm> algs);

    /**
     * Adds the specified signature algorithms to the parser's total set of supported signature algorithms,
     * replacing any existing algorithms with the same exact (CaSe-SeNsItIvE) {@link Identifiable#getId() id}s.
     * If the parser encounters a JWS {@code alg} header value that equals a signature algorithm's
     * {@link Identifiable#getId() id}, that algorithm will be used for signature verification.
     *
     * <p>There may be only one registered {@code SecureDigestAlgorithm} per algorithm {@code id}, and the
     * {@code algs} collection is added in iteration order; if a duplicate id is found when iterating the
     * {@code algs} argument, the later algorithm will evict any existing algorithm with the same {@code id}.</p>
     *
     * <p><b>Standard Algorithms and Overrides</b></p>
     *
     * <p>All JWA standard signature and MAC algorithms in {@link Jwts.SIG} are supported by default and do not need
     * to be added via this method, but beware: <b>any algorithm in the {@code algs} collection with a
     * JWA standard {@link Identifiable#getId() id} will replace the JJWT standard
     * algorithm implementation</b>. This is to allow application developers to favor their own implementations over
     * JJWT's default implementations if necessary (for example, to support legacy or custom behavior).
     *
     * @param algs collection of signature algorithms to add to the parser's total set of supported signature
     *             algorithms, replacing any existing algorithms with the same exact (CaSe-SeNsItIvE)
     *             {@link Identifiable#getId() id}s.
     * @return the builder for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1.1">Algorithm Name (id) requirements</a>
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addSignatureAlgorithms(Collection<? extends SecureDigestAlgorithm<?, ?>> algs);

    /**
     * Adds the specified key management algorithms to the parser's total set of supported key algorithms,
     * replacing any existing algorithms with the same exact (CaSe-SeNsItIvE) {@link KeyAlgorithm#getId() id}s.
     * If the parser encounters a JWE {@code alg} header value that equals a key management algorithm's
     * {@link Identifiable#getId() id}, that algorithm will be used to obtain the content decryption key.
     *
     * <p>There may be only one registered {@code KeyAlgorithm} per algorithm {@code id}, and the {@code algs}
     * collection is added in iteration order; if a duplicate id is found when iterating the {@code algs}
     * argument, the later algorithm will evict any existing algorithm with the same {@code id}.</p>
     *
     * <p><b>Standard Algorithms and Overrides</b></p>
     *
     * <p>All JWA standard key management algorithms in {@link Jwts.KEY} are supported by default and do not need
     * to be added via this method, but beware: <b>any algorithm in the {@code algs} collection with a
     * JWA standard {@link Identifiable#getId() id} will replace the JJWT standard algorithm implementation</b>.
     * This is to allow application developers to favor their own implementations over JJWT's default implementations
     * if necessary (for example, to support legacy or custom behavior).
     *
     * @param algs collection of key management algorithms to add to the parser's total set of supported key
     *             management algorithms, replacing any existing algorithms with the same exact (CaSe-SeNsItIvE)
     *             {@link KeyAlgorithm#getId() id}s.
     * @return the builder for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    JwtParserBuilder addKeyAlgorithms(Collection<? extends KeyAlgorithm<?, ?>> algs);

    /**
     * <p><b>Deprecated as of JJWT JJWT_RELEASE_VERSION. This method will be removed before the 1.0 release.</b></p>
     *
     * <p>This method has been deprecated as of JJWT version JJWT_RELEASE_VERSION because it imposed unnecessary
     * implementation requirements on application developers when simply adding to a compression algorithm collection
     * would suffice.  Use the {@link #addCompressionAlgorithms(Collection)} method instead to add
     * any custom algorithm implementations without needing to also implement a Locator implementation.</p>
     *
     * <p><b>Previous Documentation</b></p>
     * <p>
     * Sets the {@link CompressionCodecResolver} used to acquire the {@link CompressionCodec} that should be used to
     * decompress the JWT body. If the parsed JWT is not compressed, this resolver is not used.
     *
     * <p><b>WARNING:</b> Compression is not defined by the JWS Specification - only the JWE Specification - and it is
     * not expected that other libraries (including JJWT versions &lt; 0.6.0) are able to consume a compressed JWS
     * body correctly.</p>
     *
     * <p><b>Default Support</b></p>
     *
     * <p>JJWT's default {@link JwtParser} implementation supports both the {@link Jwts.ZIP#DEF DEF}
     * and {@link Jwts.ZIP#GZIP GZIP} algorithms by default - you do not need to
     * specify a {@code CompressionCodecResolver} in these cases.</p>
     *
     * @param compressionCodecResolver the compression codec resolver used to decompress the JWT body.
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of {@link #addCompressionAlgorithms(Collection)}.
     * This method will be removed before the 1.0 release.
     */
    @Deprecated
    JwtParserBuilder setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver);

    /**
     * Perform Base64Url decoding with the specified Decoder
     *
     * <p>JJWT uses a spec-compliant decoder that works on all supported JDK versions, but you may call this method
     * to specify a different decoder if you desire.</p>
     *
     * @param base64UrlDecoder the decoder to use when Base64Url-decoding
     * @return the parser builder for method chaining.
     * @deprecated since JJWT_RELEASE_VERSION in favor of the shorter and more modern builder-style named
     * {@link #decoder(Decoder)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    JwtParserBuilder base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder);

    /**
     * Perform Base64Url decoding with the specified Decoder
     *
     * <p>JJWT uses a spec-compliant decoder that works on all supported JDK versions, but you may call this method
     * to specify a different decoder if you desire.</p>
     *
     * @param base64UrlDecoder the decoder to use when Base64Url-decoding
     * @return the parser builder for method chaining.
     */
    JwtParserBuilder decoder(Decoder<String, byte[]> base64UrlDecoder);

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
     * @deprecated since JJWT_RELEASE_VERSION in favor of the shorter and more modern builder-style named
     * {@link #deserializer(Deserializer)}. This method will be removed before the JJWT 1.0 release.
     */
    @Deprecated
    JwtParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer);

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
    JwtParserBuilder deserializer(Deserializer<Map<String, ?>> deserializer);

    /**
     * Returns an immutable/thread-safe {@link JwtParser} created from the configuration from this JwtParserBuilder.
     *
     * @return an immutable/thread-safe JwtParser created from the configuration from this JwtParserBuilder.
     */
    JwtParser build();
}

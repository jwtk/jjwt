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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.InvalidClaimException;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import io.jsonwebtoken.impl.lang.ConstantFunction;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.impl.security.ConstantKeyLocator;
import io.jsonwebtoken.impl.security.DefaultAeadResult;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.DefaultVerifySignatureRequest;
import io.jsonwebtoken.impl.security.EncryptionAlgorithmsBridge;
import io.jsonwebtoken.impl.security.KeyAlgorithmsBridge;
import io.jsonwebtoken.impl.security.SignatureAlgorithmsBridge;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.PayloadSupplier;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithms;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest;
import io.jsonwebtoken.security.VerifySignatureRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultJwtParser implements JwtParser {

    private static final int MILLISECONDS_PER_SECOND = 1000;

    private static final JwtTokenizer jwtTokenizer = new JwtTokenizer();

    public static final String MISSING_JWS_ALG_MSG =
        "JWS header does not contain a required 'alg' (Algorithm) header parameter.  " +
            "This header parameter is mandatory per the JWS Specification, Section 4.1.1. See " +
            "https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1 for more information.";

    public static final String MISSING_JWE_ALG_MSG =
        "JWE header does not contain a required 'alg' (Algorithm) header parameter.  " +
            "This header parameter is mandatory per the JWE Specification, Section 4.1.1. See " +
            "https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1 for more information.";

    private static final String MISSING_ENC_MSG =
        "JWE header does not contain a required 'enc' (Encryption Algorithm) header parameter.  " +
            "This header parameter is mandatory per the JWE Specification, Section 4.1.2. See " +
            "https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2 for more information.";

    private static <H extends Header<H>, R extends Identifiable> Function<H, R> backup(String id, String msg, Collection<R> extras) {
        if (Collections.isEmpty(extras)) {
            return ConstantFunction.forNull();
        } else {
            return new IdLocator<>(id, msg, new IdRegistry<>(extras), ConstantFunction.<H, R>forNull());
        }
    }

    private static <H extends Header<H>, R extends Identifiable> Function<H, R> locFn(String id, String msg, Function<String, R> reg, Collection<R> extras) {
        Function<H,R> backup = backup(id, msg, extras);
        return new IdLocator<>(id, msg, reg, backup);
    }

    private static Function<JwsHeader, SignatureAlgorithm<?, ?>> sigFn(Collection<SignatureAlgorithm<?, ?>> extras) {
        return locFn(JwsHeader.ALGORITHM, MISSING_JWS_ALG_MSG, SignatureAlgorithmsBridge.REGISTRY, extras);
    }

    private static Function<JweHeader, SymmetricAeadAlgorithm> encFn(Collection<SymmetricAeadAlgorithm> extras) {
        return locFn(JweHeader.ENCRYPTION_ALGORITHM, MISSING_ENC_MSG, EncryptionAlgorithmsBridge.REGISTRY, extras);
    }

    private static Function<JweHeader, KeyAlgorithm<?, ?>> keyFn(Collection<KeyAlgorithm<?, ?>> extras) {
        return locFn(JweHeader.ALGORITHM, MISSING_JWE_ALG_MSG, KeyAlgorithmsBridge.REGISTRY, extras);
    }

    // TODO: make the following fields final for v1.0
    private Provider provider;

    @SuppressWarnings("deprecation") // will remove for 1.0
    private SigningKeyResolver signingKeyResolver;

    @SuppressWarnings("rawtypes")
    private Function<Header, CompressionCodec> compressionCodecLocator;

    private final Function<JwsHeader, SignatureAlgorithm<?, ?>> signatureAlgorithmLocator;

    private final Function<JweHeader, SymmetricAeadAlgorithm> encryptionAlgorithmLocator;

    private final Function<JweHeader, KeyAlgorithm<?, ?>> keyAlgorithmLocator;

    private final Function<?, Key> keyLocator;

    private Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;

    private Deserializer<Map<String, ?>> deserializer;

    private Claims expectedClaims = new DefaultClaims();

    private Clock clock = DefaultClock.INSTANCE;

    private long allowedClockSkewMillis = 0;

    /**
     * TODO: remove this constructor before 1.0
     *
     * @deprecated for backward compatibility only, see other constructors.
     */
    @SuppressWarnings("DeprecatedIsStillUsed") // will remove before 1.0
    @Deprecated
    public DefaultJwtParser() {
        ConstantKeyLocator<?> constantKeyLocator = new ConstantKeyLocator<>(null, null);
        this.keyLocator = constantKeyLocator;
        this.signingKeyResolver = constantKeyLocator;
        this.signatureAlgorithmLocator = sigFn(Collections.<SignatureAlgorithm<?, ?>>emptyList());
        this.keyAlgorithmLocator = keyFn(Collections.<KeyAlgorithm<?, ?>>emptyList());
        this.encryptionAlgorithmLocator = encFn(Collections.<SymmetricAeadAlgorithm>emptyList());
        this.compressionCodecLocator = new CompressionCodecLocator<>(new DefaultCompressionCodecResolver());
    }

    @SuppressWarnings("deprecation") //SigningKeyResolver will be removed for 1.0
    DefaultJwtParser(Provider provider,
                     SigningKeyResolver signingKeyResolver,
                     Function<?,Key> keyLocator,
                     Clock clock,
                     long allowedClockSkewMillis,
                     Claims expectedClaims,
                     Decoder<String, byte[]> base64UrlDecoder,
                     Deserializer<Map<String, ?>> deserializer,
                     CompressionCodecResolver compressionCodecResolver,
                     Collection<SignatureAlgorithm<?, ?>> extraSigAlgs,
                     Collection<KeyAlgorithm<?, ?>> extraKeyAlgs,
                     Collection<SymmetricAeadAlgorithm> extraEncAlgs) {
        this.provider = provider;
        this.signingKeyResolver = Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.keyLocator = Assert.notNull(keyLocator, "Key Locator cannot be null.");
        this.clock = clock;
        this.allowedClockSkewMillis = allowedClockSkewMillis;
        this.expectedClaims = expectedClaims;
        this.base64UrlDecoder = base64UrlDecoder;
        this.deserializer = deserializer;
        this.signatureAlgorithmLocator = sigFn(extraSigAlgs);
        this.keyAlgorithmLocator = keyFn(extraKeyAlgs);
        this.encryptionAlgorithmLocator = encFn(extraEncAlgs);
        this.compressionCodecLocator = new CompressionCodecLocator<>(compressionCodecResolver);
    }

    @Override
    public JwtParser deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        Assert.notNull(deserializer, "deserializer cannot be null.");
        this.deserializer = deserializer;
        return this;
    }

    @Override
    public JwtParser base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder) {
        Assert.notNull(base64UrlDecoder, "base64UrlDecoder cannot be null.");
        this.base64UrlDecoder = base64UrlDecoder;
        return this;
    }

    @Override
    public JwtParser requireIssuedAt(Date issuedAt) {
        expectedClaims.setIssuedAt(issuedAt);
        return this;
    }

    @Override
    public JwtParser requireIssuer(String issuer) {
        expectedClaims.setIssuer(issuer);
        return this;
    }

    @Override
    public JwtParser requireAudience(String audience) {
        expectedClaims.setAudience(audience);
        return this;
    }

    @Override
    public JwtParser requireSubject(String subject) {
        expectedClaims.setSubject(subject);
        return this;
    }

    @Override
    public JwtParser requireId(String id) {
        expectedClaims.setId(id);
        return this;
    }

    @Override
    public JwtParser requireExpiration(Date expiration) {
        expectedClaims.setExpiration(expiration);
        return this;
    }

    @Override
    public JwtParser requireNotBefore(Date notBefore) {
        expectedClaims.setNotBefore(notBefore);
        return this;
    }

    @Override
    public JwtParser require(String claimName, Object value) {
        Assert.hasText(claimName, "claim name cannot be null or empty.");
        Assert.notNull(value, "The value cannot be null for claim name: " + claimName);
        expectedClaims.put(claimName, value);
        return this;
    }

    @Override
    public JwtParser setClock(Clock clock) {
        Assert.notNull(clock, "Clock instance cannot be null.");
        this.clock = clock;
        return this;
    }

    @Override
    public JwtParser setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException {
        Assert.isTrue(seconds <= DefaultJwtParserBuilder.MAX_CLOCK_SKEW_MILLIS, DefaultJwtParserBuilder.MAX_CLOCK_SKEW_ILLEGAL_MSG);
        this.allowedClockSkewMillis = Math.max(0, seconds * MILLISECONDS_PER_SECOND);
        return this;
    }

    @Override
    public JwtParser setSigningKey(byte[] key) {
        Assert.notEmpty(key, "signing key cannot be null or empty.");
        return setSigningKey(Keys.hmacShaKeyFor(key));
    }

    @Override
    public JwtParser setSigningKey(String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "signing key cannot be null or empty.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return setSigningKey(bytes);
    }

    @Override
    public JwtParser setSigningKey(final Key key) {
        Assert.notNull(key, "signing key cannot be null.");
        setSigningKeyResolver(new ConstantKeyLocator<>(key, null));
        return this;
    }

    @SuppressWarnings("deprecation") // required until 1.0
    @Override
    public JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.signingKeyResolver = signingKeyResolver;
        return this;
    }

    @Override
    public JwtParser setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver) {
        Assert.notNull(compressionCodecResolver, "compressionCodecResolver cannot be null.");
        this.compressionCodecLocator = new CompressionCodecLocator<>(compressionCodecResolver);
        return this;
    }

    @Override
    public boolean isSigned(String compact) {
        if (compact == null) {
            return false;
        }

        int delimiterCount = 0;

        for (int i = 0; i < compact.length(); i++) {
            char c = compact.charAt(i);

            if (delimiterCount == 2) {
                return !Character.isWhitespace(c) && c != SEPARATOR_CHAR;
            }

            if (c == SEPARATOR_CHAR) {
                delimiterCount++;
            }
        }

        return false;
    }

    @Override
    public Jwt<?, ?> parse(String compact) throws ExpiredJwtException, MalformedJwtException, SignatureException {

        // TODO, this logic is only need for a now deprecated code path
        // remove this block in v1.0 (the equivalent is already in DefaultJwtParserBuilder)
        if (this.deserializer == null) {
            // try to find one based on the services available
            // TODO: This util class will throw a UnavailableImplementationException here to retain behavior of previous version, remove in v1.0
            //noinspection deprecation
            this.deserializer = LegacyServices.loadFirst(Deserializer.class);
        }

        Assert.hasText(compact, "JWT String cannot be null or empty.");

        final TokenizedJwt tokenized = jwtTokenizer.tokenize(compact);
        final String base64UrlHeader = tokenized.getProtected();
        if (!Strings.hasText(base64UrlHeader)) {
            String msg = "Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).";
            throw new MalformedJwtException(msg);
        }

        // =============== Header =================
        final byte[] headerBytes = base64UrlDecode(base64UrlHeader, "protected header");
        String origValue = new String(headerBytes, Strings.UTF_8);
        Map<String, ?> m = readValue(origValue, "protected header");
        Header<?> header = tokenized.createHeader(m);

        // https://tools.ietf.org/html/rfc7515#section-10.7 , second-to-last bullet point, note the use of 'always':
        //
        //   *  Require that the "alg" Header Parameter be carried in the JWS
        //      Protected Header.  (This is always the case when using the JWS
        //      Compact Serialization and is the approach taken by CMS [RFC6211].)
        //
        final String alg = Strings.clean(header.getAlgorithm());
        if (!Strings.hasText(alg)) {
            String msg = "Compact JWT strings MUST always have an 'alg' (Algorithm) header value per " +
                "https://tools.ietf.org/html/rfc7515#section-4.1.1 and " +
                "https://tools.ietf.org/html/rfc7516#section-4.1.1. Also see " +
                "https://tools.ietf.org/html/rfc7515#section-10.7 for more information.";
            throw new MalformedJwtException(msg);
        }

        // =============== Body =================
        CompressionCodec compressionCodec = compressionCodecLocator.apply(header);
        byte[] bytes = base64UrlDecode(tokenized.getBody(), "payload"); // Only JWS body can be empty per https://github.com/jwtk/jjwt/pull/540
        if (tokenized instanceof TokenizedJwe && Arrays.length(bytes) == 0) {
            String msg = "Compact JWE strings MUST always contain a payload (ciphertext).";
            throw new MalformedJwtException(msg);
        }
        if (compressionCodec != null) {
            bytes = compressionCodec.decompress(bytes);
        }

        byte[] iv = null;
        byte[] tag = null;
        if (tokenized instanceof TokenizedJwe) { //need to decrypt the ciphertext

            TokenizedJwe tokenizedJwe = (TokenizedJwe) tokenized;
            JweHeader jweHeader = (JweHeader) header;

            byte[] cekBytes = new byte[0]; //ignored unless using an encrypted key algorithm
            String base64Url = tokenizedJwe.getEncryptedKey();
            if (Strings.hasText(base64Url)) {
                cekBytes = base64UrlDecode(base64Url, "JWE encrypted key");
                if (Arrays.length(cekBytes) == 0) {
                    String msg = "Compact JWE string represents an encrypted key, but the key is empty.";
                    throw new MalformedJwtException(msg);
                }
            }

            base64Url = tokenizedJwe.getIv();
            if (Strings.hasText(base64Url)) {
                iv = base64UrlDecode(base64Url, "JWE Initialization Vector");
            }
            if (Arrays.length(iv) == 0) {
                String msg = "Compact JWE strings must always contain an Initialization Vector.";
                throw new MalformedJwtException(msg);
            }

            // This is intentional - the AAD (Additional Authenticated Data) scheme for compact JWEs is to use
            // the ASCII bytes of the raw base64url text as the AAD, and *not* the base64url-decoded bytes per
            // https://datatracker.ietf.org/doc/html/rfc7516#section-5.1, Step 14.
            final byte[] aad = base64UrlHeader.getBytes(StandardCharsets.US_ASCII);

            base64Url = tokenizedJwe.getDigest();
            if (Strings.hasText(base64Url)) {
                tag = base64UrlDecode(base64Url, "JWE AAD Authentication Tag");
            }
            if (Arrays.length(tag) == 0) {
                String msg = "Compact JWE strings must always contain an AAD Authentication Tag.";
                throw new MalformedJwtException(msg);
            }

            String enc = jweHeader.getEncryptionAlgorithm();
            if (!Strings.hasText(enc)) {
                throw new MalformedJwtException(MISSING_ENC_MSG);
            }
            final SymmetricAeadAlgorithm encAlg = this.encryptionAlgorithmLocator.apply(jweHeader);
            if (encAlg == null) {
                String msg = "Unrecognized JWE encryption algorithm identifier: " + enc;
                throw new UnsupportedJwtException(msg);
            }

            @SuppressWarnings("rawtypes") final KeyAlgorithm keyAlg = this.keyAlgorithmLocator.apply(jweHeader);
            if (keyAlg == null) {
                String msg = "Unrecognized JWE key management algorithm: " + alg;
                throw new UnsupportedJwtException(msg);
            }

            final Key key = ((Function<JweHeader,Key>)this.keyLocator).apply(jweHeader);
            if (key == null) {
                String msg = "No key available for the '" + keyAlg.getId() + "' key management algorithm. Unable to " +
                    "perform '" + encAlg + "' decryption.";
                throw new UnsupportedJwtException(msg);
            }

            KeyRequest<byte[], ?> request = new DefaultKeyRequest<>(this.provider, null, cekBytes, key, jweHeader);
            final SecretKey cek = keyAlg.getDecryptionKey(request);

            SymmetricAeadDecryptionRequest decryptRequest =
                new DefaultAeadResult(this.provider, null, bytes, cek, aad, tag, iv);
            PayloadSupplier<byte[]> result = encAlg.decrypt(decryptRequest);
            bytes = result.getPayload();
        }

        String payload = new String(bytes, Strings.UTF_8);

        Claims claims = null;
        if (!payload.isEmpty() && payload.charAt(0) == '{' && payload.charAt(payload.length() - 1) == '}') { //likely to be json, parse it:
            Map<String, ?> claimsMap = readValue(payload, "claims");
            claims = new DefaultClaims(claimsMap);
        }

        Jwt<?, ?> jwt;
        Object body = claims != null ? claims : payload;
        if (header instanceof JweHeader) {
            jwt = new DefaultJwe<>((JweHeader)header, body, iv, tag);
        } else { // JWS
            if (!Strings.hasText(tokenized.getDigest()) && SignatureAlgorithms.NONE.getId().equalsIgnoreCase(alg)) {
                //noinspection rawtypes
                jwt = new DefaultJwt(header, body);
            } else {
                jwt = new DefaultJws<>((JwsHeader)header, body, tokenized.getDigest());
            }
        }

        // =============== Signature =================
        if (jwt instanceof Jws) { // it's a JWS, validate the signature

            Jws<?> jws = (Jws<?>) jwt;

            final JwsHeader jwsHeader = jws.getHeader();

            SignatureAlgorithm<?,Key> algorithm = (SignatureAlgorithm<?,Key>)signatureAlgorithmLocator.apply(jwsHeader);
            if (algorithm == null) {
                String msg = "Unrecognized JWS algorithm identifier: " + alg;
                throw new UnsupportedJwtException(msg);
            }

            String digest = tokenized.getDigest();

            if (SignatureAlgorithms.NONE.equals(algorithm) && Strings.hasText(digest)) {
                //'none' algorithm, but it has a signature.  This is invalid:
                String msg = "The JWS header references signature algorithm '" + alg + "' yet the compact JWS string has a digest/signature. This is not permitted per https://tools.ietf.org/html/rfc7518#section-3.6.";
                throw new MalformedJwtException(msg);
            } else if (!Strings.hasText(digest)) {
                String msg = "The JWS header references signature algorithm '" + alg + "' but the compact JWS string does not have a signature token.";
                throw new MalformedJwtException(msg);
            }

            assert this.signingKeyResolver != null : "SigningKeyResolver cannot be null (invariant).";

            //digitally signed, let's assert the signature:
            Key key;
            if (claims != null) {
                key = signingKeyResolver.resolveSigningKey(jwsHeader, claims);
            } else {
                key = signingKeyResolver.resolveSigningKey(jwsHeader, payload);
            }
            Assert.notNull(key, "A signature verification key is required if the specified JWT is digitally signed.");

            //re-create the jwt part without the signature.  This is what is needed for signature verification:
            String jwtWithoutSignature = tokenized.getProtected() + SEPARATOR_CHAR + tokenized.getBody();

            byte[] data = jwtWithoutSignature.getBytes(StandardCharsets.US_ASCII);
            byte[] signature = base64UrlDecode(tokenized.getDigest(), "JWS signature");

            try {
                VerifySignatureRequest<Key> request =
                    new DefaultVerifySignatureRequest<>(this.provider, null, data, key, signature);

                if (!algorithm.verify(request)) {
                    String msg = "JWT signature does not match locally computed signature. JWT validity cannot be " +
                        "asserted and should not be trusted.";
                    throw new SignatureException(msg);
                }
            } catch (WeakKeyException e) {
                throw e;
            } catch (InvalidKeyException | IllegalArgumentException e) {
                String algId = algorithm.getId();
                String msg = "The parsed JWT indicates it was signed with the " + algId + " signature " +
                    "algorithm, but the specified verification key of type " + key.getClass().getName() +
                    " may not be used to validate " + algId + " signatures.  Because the verification " +
                    "key reflects a specific and expected algorithm, and the JWT does not reflect " +
                    "this algorithm, it is likely that the JWT was not expected and therefore should not be " +
                    "trusted.  Another possibility is that the parser was supplied with the incorrect " +
                    "verification key, but this cannot be assumed for security reasons.";
                throw new UnsupportedJwtException(msg, e);
            }
        }

        final boolean allowSkew = this.allowedClockSkewMillis > 0;

        //since 0.3:
        if (claims != null) {

            final Date now = this.clock.now();
            long nowTime = now.getTime();

            //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1.4
            //token MUST NOT be accepted on or after any specified exp time:
            Date exp = claims.getExpiration();
            if (exp != null) {

                long maxTime = nowTime - this.allowedClockSkewMillis;
                Date max = allowSkew ? new Date(maxTime) : now;
                if (max.after(exp)) {
                    String expVal = DateFormats.formatIso8601(exp, false);
                    String nowVal = DateFormats.formatIso8601(now, false);

                    long differenceMillis = maxTime - exp.getTime();

                    String msg = "JWT expired at " + expVal + ". Current time: " + nowVal + ", a difference of " +
                        differenceMillis + " milliseconds.  Allowed clock skew: " +
                        this.allowedClockSkewMillis + " milliseconds.";
                    throw new ExpiredJwtException(header, claims, msg);
                }
            }

            //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1.5
            //token MUST NOT be accepted before any specified nbf time:
            Date nbf = claims.getNotBefore();
            if (nbf != null) {

                long minTime = nowTime + this.allowedClockSkewMillis;
                Date min = allowSkew ? new Date(minTime) : now;
                if (min.before(nbf)) {
                    String nbfVal = DateFormats.formatIso8601(nbf, false);
                    String nowVal = DateFormats.formatIso8601(now, false);

                    long differenceMillis = nbf.getTime() - minTime;

                    String msg = "JWT must not be accepted before " + nbfVal + ". Current time: " + nowVal +
                        ", a difference of " +
                        differenceMillis + " milliseconds.  Allowed clock skew: " +
                        this.allowedClockSkewMillis + " milliseconds.";
                    throw new PrematureJwtException(header, claims, msg);
                }
            }

            validateExpectedClaims(header, claims);
        }

        return jwt;
    }

    /**
     * @since 0.10.0
     */
    private static Object normalize(Object o) {
        if (o instanceof Integer) {
            o = ((Integer) o).longValue();
        }
        return o;
    }

    private void validateExpectedClaims(Header<?> header, Claims claims) {

        for (String expectedClaimName : expectedClaims.keySet()) {

            Object expectedClaimValue = normalize(expectedClaims.get(expectedClaimName));
            Object actualClaimValue = normalize(claims.get(expectedClaimName));

            if (expectedClaimValue instanceof Date) {
                try {
                    actualClaimValue = claims.get(expectedClaimName, Date.class);
                } catch (Exception e) {
                    String msg = "JWT Claim '" + expectedClaimName + "' was expected to be a Date, but its value " +
                        "cannot be converted to a Date using current heuristics.  Value: " + actualClaimValue;
                    throw new IncorrectClaimException(header, claims, msg);
                }
            }

            InvalidClaimException invalidClaimException = null;

            if (actualClaimValue == null) {

                String msg = String.format(ClaimJwtException.MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE,
                    expectedClaimName, expectedClaimValue);

                invalidClaimException = new MissingClaimException(header, claims, msg);

            } else if (!expectedClaimValue.equals(actualClaimValue)) {

                String msg = String.format(ClaimJwtException.INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE,
                    expectedClaimName, expectedClaimValue, actualClaimValue);

                invalidClaimException = new IncorrectClaimException(header, claims, msg);
            }

            if (invalidClaimException != null) {
                invalidClaimException.setClaimName(expectedClaimName);
                invalidClaimException.setClaimValue(expectedClaimValue);
                throw invalidClaimException;
            }
        }
    }

    @Override
    public <T> T parse(String compact, JwtHandler<T> handler)
        throws ExpiredJwtException, MalformedJwtException, SignatureException {
        Assert.notNull(handler, "JwtHandler argument cannot be null.");
        Assert.hasText(compact, "JWT String argument cannot be null or empty.");

        Jwt<?, ?> jwt = parse(compact);

        if (jwt instanceof Jws) {
            Jws<?> jws = (Jws<?>) jwt;
            Object body = jws.getBody();
            if (body instanceof Claims) {
                return handler.onClaimsJws((Jws<Claims>) jws);
            } else {
                return handler.onPlaintextJws((Jws<String>) jws);
            }
        } else if (jwt instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>) jwt;
            Object body = jwe.getBody();
            if (body instanceof Claims) {
                return handler.onClaimsJwe((Jwe<Claims>) jwe);
            } else {
                return handler.onPlaintextJwe((Jwe<String>) jwe);
            }
        } else {
            Object body = jwt.getBody();
            if (body instanceof Claims) {
                return handler.onClaimsJwt((Jwt<?, Claims>) jwt);
            } else {
                return handler.onPlaintextJwt((Jwt<?, String>) jwt);
            }
        }
    }

    @Override
    public Jwt<?, String> parsePlaintextJwt(String plaintextJwt) {
        return parse(plaintextJwt, new JwtHandlerAdapter<Jwt<?, String>>() {
            @Override
            public Jwt<?, String> onPlaintextJwt(Jwt<?, String> jwt) {
                return jwt;
            }
        });
    }

    @Override
    public Jwt<?, Claims> parseClaimsJwt(String claimsJwt) {
        try {
            return parse(claimsJwt, new JwtHandlerAdapter<Jwt<?, Claims>>() {
                @Override
                public Jwt<?, Claims> onClaimsJwt(Jwt<?, Claims> jwt) {
                    return jwt;
                }
            });
        } catch (IllegalArgumentException iae) {
            throw new UnsupportedJwtException("Signed JWSs are not supported.", iae);
        }
    }

    @Override
    public Jws<String> parsePlaintextJws(String plaintextJws) {
        try {
            return parse(plaintextJws, new JwtHandlerAdapter<Jws<String>>() {
                @Override
                public Jws<String> onPlaintextJws(Jws<String> jws) {
                    return jws;
                }
            });
        } catch (IllegalArgumentException iae) {
            throw new UnsupportedJwtException("Signed JWSs are not supported.", iae);
        }
    }

    @Override
    public Jws<Claims> parseClaimsJws(String claimsJws) {
        return parse(claimsJws, new JwtHandlerAdapter<Jws<Claims>>() {
            @Override
            public Jws<Claims> onClaimsJws(Jws<Claims> jws) {
                return jws;
            }
        });
    }

    @Override
    public Jwe<String> parsePlaintextJwe(String plaintextJwe) throws JwtException {
        return parse(plaintextJwe, new JwtHandlerAdapter<Jwe<String>>() {
            @Override
            public Jwe<String> onPlaintextJwe(Jwe<String> jwe) {
                return jwe;
            }
        });
    }

    @Override
    public Jwe<Claims> parseClaimsJwe(String claimsJwe) throws JwtException {
        return parse(claimsJwe, new JwtHandlerAdapter<Jwe<Claims>>() {
            @Override
            public Jwe<Claims> onClaimsJwe(Jwe<Claims> jwe) {
                return jwe;
            }
        });
    }

    protected byte[] base64UrlDecode(String base64UrlEncoded, String name) {
        try {
            return base64UrlDecoder.decode(base64UrlEncoded);
        } catch (DecodingException e) {
            String msg = "Invalid Base64Url " + name + ": " + base64UrlEncoded;
            throw new MalformedJwtException(msg, e);
        }
    }

    protected Map<String, ?> readValue(String val, final String name) {
        try {
            byte[] bytes = val.getBytes(Strings.UTF_8);
            return deserializer.deserialize(bytes);
        } catch (DeserializationException e) {
            throw new MalformedJwtException("Unable to read " + name + " JSON: " + val, e);
        }
    }
}

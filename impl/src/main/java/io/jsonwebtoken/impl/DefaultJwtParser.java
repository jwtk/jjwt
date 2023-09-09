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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.security.DefaultAeadResult;
import io.jsonwebtoken.impl.security.DefaultDecryptionKeyRequest;
import io.jsonwebtoken.impl.security.DefaultVerifySecureDigestRequest;
import io.jsonwebtoken.impl.security.LocatingKeyResolver;
import io.jsonwebtoken.impl.security.ProviderKey;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptAeadRequest;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Message;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultJwtParser implements JwtParser {

    static final char SEPARATOR_CHAR = '.';

    private static final JwtTokenizer jwtTokenizer = new JwtTokenizer();

    static final String PRIV_KEY_VERIFY_MSG = "PrivateKeys may not be used to verify digital signatures. " +
            "PrivateKeys are used to sign, and PublicKeys are used to verify.";

    static final String PUB_KEY_DECRYPT_MSG = "PublicKeys may not be used to decrypt data. PublicKeys are " +
            "used to encrypt, and PrivateKeys are used to decrypt.";

    public static final String INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE = "Expected %s claim to be: %s, but was: %s.";

    public static final String MISSING_EXPECTED_CLAIM_VALUE_MESSAGE_TEMPLATE =
            "Missing expected '%s' value in '%s' claim %s.";
    public static final String MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE = "Expected %s claim to be: %s, but was not " +
            "present in the JWT claims.";

    public static final String MISSING_JWS_ALG_MSG = "JWS header does not contain a required 'alg' (Algorithm) " +
            "header parameter.  This header parameter is mandatory per the JWS Specification, Section 4.1.1. See " +
            "https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1 for more information.";

    public static final String MISSING_JWE_ALG_MSG = "JWE header does not contain a required 'alg' (Algorithm) " +
            "header parameter.  This header parameter is mandatory per the JWE Specification, Section 4.1.1. See " +
            "https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1 for more information.";

    public static final String MISSING_JWS_DIGEST_MSG_FMT = "The JWS header references signature algorithm '%s' but " +
            "the compact JWE string is missing the required signature.";

    public static final String MISSING_JWE_DIGEST_MSG_FMT = "The JWE header references key management algorithm '%s' " +
            "but the compact JWE string is missing the required AAD authentication tag.";

    private static final String MISSING_ENC_MSG = "JWE header does not contain a required 'enc' (Encryption " +
            "Algorithm) header parameter.  This header parameter is mandatory per the JWE Specification, " +
            "Section 4.1.2. See https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2 for more information.";

    private static final String UNSECURED_DISABLED_MSG_PREFIX = "Unsecured JWSs (those with an " +
            DefaultHeader.ALGORITHM + " header value of '" + Jwts.SIG.NONE.getId() + "') are disallowed by " +
            "default as mandated by https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6. If you wish to " +
            "allow them to be parsed, call the JwtParserBuilder.enableUnsecured() method, but please read the " +
            "security considerations covered in that method's JavaDoc before doing so. Header: ";

    private static final String JWE_NONE_MSG = "JWEs do not support key management " + DefaultHeader.ALGORITHM +
            " header value '" + Jwts.SIG.NONE.getId() + "' per " +
            "https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1";

    private static final String JWS_NONE_SIG_MISMATCH_MSG = "The JWS header references signature algorithm '" +
            Jwts.SIG.NONE.getId() + "' yet the compact JWS string contains a signature. This is not permitted " +
            "per https://tools.ietf.org/html/rfc7518#section-3.6.";
    private static final String UNPROTECTED_DECOMPRESSION_MSG = "The JWT header references compression algorithm " +
            "'%s', but payload decompression for Unsecured JWTs (those with an " + DefaultHeader.ALGORITHM +
            " header value of '" + Jwts.SIG.NONE.getId() + "') are " + "disallowed by default to protect " +
            "against [Denial of Service attacks](" +
            "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf).  If you " +
            "wish to enable Unsecure JWS payload decompression, call the JwtParserBuilder." +
            "enableUnsecuredDecompression() method, but please read the security considerations covered in that " +
            "method's JavaDoc before doing so.";

    private final Provider provider;

    @SuppressWarnings("deprecation")
    private final SigningKeyResolver signingKeyResolver;

    private final boolean enableUnsecured;

    private final boolean enableUnsecuredDecompression;

    private final Function<JwsHeader, SecureDigestAlgorithm<?, ?>> sigAlgFn;

    private final Function<JweHeader, AeadAlgorithm> encAlgFn;

    private final Function<JweHeader, KeyAlgorithm<?, ?>> keyAlgFn;

    private final Function<Header, CompressionAlgorithm> zipAlgFn;

    private final Locator<? extends Key> keyLocator;

    private final Decoder<String, byte[]> decoder;

    private final Deserializer<Map<String, ?>> deserializer;

    private final ClaimsBuilder expectedClaims;

    private final Clock clock;

    private final long allowedClockSkewMillis;

    //SigningKeyResolver will be removed for 1.0:
    @SuppressWarnings("deprecation")
    DefaultJwtParser(Provider provider,
                     SigningKeyResolver signingKeyResolver,
                     boolean enableUnsecured,
                     boolean enableUnsecuredDecompression,
                     Locator<? extends Key> keyLocator,
                     Clock clock,
                     long allowedClockSkewMillis,
                     DefaultClaims expectedClaims,
                     Decoder<String, byte[]> base64UrlDecoder,
                     Deserializer<Map<String, ?>> deserializer,
                     CompressionCodecResolver compressionCodecResolver,
                     Collection<CompressionAlgorithm> extraZipAlgs,
                     Collection<SecureDigestAlgorithm<?, ?>> extraSigAlgs,
                     Collection<KeyAlgorithm<?, ?>> extraKeyAlgs,
                     Collection<AeadAlgorithm> extraEncAlgs) {
        this.provider = provider;
        this.enableUnsecured = enableUnsecured;
        this.enableUnsecuredDecompression = enableUnsecuredDecompression;
        this.signingKeyResolver = signingKeyResolver;
        this.keyLocator = Assert.notNull(keyLocator, "Key Locator cannot be null.");
        this.clock = Assert.notNull(clock, "Clock cannot be null.");
        this.allowedClockSkewMillis = allowedClockSkewMillis;
        this.expectedClaims = Jwts.claims().add(expectedClaims);
        this.decoder = Assert.notNull(base64UrlDecoder, "base64UrlDecoder cannot be null.");
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");

        this.sigAlgFn = new IdLocator<>(DefaultHeader.ALGORITHM, Jwts.SIG.get(), extraSigAlgs, MISSING_JWS_ALG_MSG);
        this.keyAlgFn = new IdLocator<>(DefaultHeader.ALGORITHM, Jwts.KEY.get(), extraKeyAlgs, MISSING_JWE_ALG_MSG);
        this.encAlgFn = new IdLocator<>(DefaultJweHeader.ENCRYPTION_ALGORITHM, Jwts.ENC.get(), extraEncAlgs, MISSING_ENC_MSG);
        this.zipAlgFn = compressionCodecResolver != null ? new CompressionCodecLocator(compressionCodecResolver) :
                new IdLocator<>(DefaultHeader.COMPRESSION_ALGORITHM, Jwts.ZIP.get(), extraZipAlgs, null);
    }

    @Override
    public boolean isSigned(String compact) {
        if (compact == null) {
            return false;
        }
        try {
            final TokenizedJwt tokenized = jwtTokenizer.tokenize(compact);
            return !(tokenized instanceof TokenizedJwe) && Strings.hasText(tokenized.getDigest());
        } catch (MalformedJwtException e) {
            return false;
        }
    }

    private static boolean hasContentType(Header header) {
        return header != null && Strings.hasText(header.getContentType());
    }


    /**
     * Returns {@code true} IFF the specified payload starts with a <code>&#123;</code> character and ends with a
     * <code>&#125;</code> character, ignoring any leading or trailing whitespace as defined by
     * {@link Character#isWhitespace(char)}.  This does not guarantee JSON, just that it is likely JSON and
     * should be passed to a JSON Deserializer to see if it is actually JSON.  If this {@code returns false}, it
     * should be considered a byte[] payload and <em>not</em> delegated to a JSON Deserializer.
     *
     * @param payload the byte array that could be JSON
     * @return {@code true} IFF the specified payload starts with a <code>&#123;</code> character and ends with a
     * <code>&#125;</code> character, ignoring any leading or trailing whitespace as defined by
     * {@link Character#isWhitespace(char)}
     * @since JJWT_RELEASE_VERSION
     */
    private static boolean isLikelyJson(byte[] payload) {

        int len = Bytes.length(payload);
        if (len == 0) {
            return false;
        }

        int maxIndex = len - 1;
        int jsonStartIndex = -1; // out of bounds means didn't find any
        int jsonEndIndex = len; // out of bounds means didn't find any

        for (int i = 0; i < len; i++) {
            int c = payload[i];
            if (c == '{') {
                jsonStartIndex = i;
                break;
            }
        }
        if (jsonStartIndex == -1) { //exhausted entire payload, didn't find starting '{', can't be a JSON object
            return false;
        }
        if (jsonStartIndex > 0) {
            // we found content at the start of the payload, but before the first '{' character, so we need to check
            // to see if any of it (when UTF-8 decoded) is not whitespace. If so, it can't be a valid JSON object.
            byte[] leading = new byte[jsonStartIndex];
            System.arraycopy(payload, 0, leading, 0, jsonStartIndex);
            String s = new String(leading, StandardCharsets.UTF_8);
            if (Strings.hasText(s)) { // found something before '{' that isn't whitespace; can't be a valid JSON object
                return false;
            }
        }

        for (int i = maxIndex; i > jsonStartIndex; i--) {
            int c = payload[i];
            if (c == '}') {
                jsonEndIndex = i;
                break;
            }
        }

        if (jsonEndIndex > maxIndex) { // found start '{' char, but no closing '} char. Can't be a JSON object
            return false;
        }

        if (jsonEndIndex < maxIndex) {
            // We found content at the end of the payload, after the last '}' character.  We need to check to see if
            // any of it (when UTF-8 decoded) is not whitespace. If so, it's not a valid JSON object payload.
            int size = maxIndex - jsonEndIndex;
            byte[] trailing = new byte[size];
            System.arraycopy(payload, jsonEndIndex + 1, trailing, 0, size);
            String s = new String(trailing, StandardCharsets.UTF_8);
            return !Strings.hasText(s); // if just whitespace after last '}', we can assume JSON and try and parse it
        }

        return true;
    }

    private void verifySignature(final TokenizedJwt tokenized, final JwsHeader jwsHeader, final String alg,
                                 @SuppressWarnings("deprecation") SigningKeyResolver resolver,
                                 Claims claims, byte[] payload) {

        Assert.notNull(resolver, "SigningKeyResolver instance cannot be null.");

        SecureDigestAlgorithm<?, Key> algorithm;
        try {
            algorithm = (SecureDigestAlgorithm<?, Key>) sigAlgFn.apply(jwsHeader);
        } catch (UnsupportedJwtException e) {
            //For backwards compatibility.  TODO: remove this try/catch block for 1.0 and let UnsupportedJwtException propagate
            String msg = "Unsupported signature algorithm '" + alg + "'";
            throw new SignatureException(msg, e);
        }
        Assert.stateNotNull(algorithm, "JWS Signature Algorithm cannot be null.");

        //digitally signed, let's assert the signature:
        Key key;
        if (claims != null) {
            key = resolver.resolveSigningKey(jwsHeader, claims);
        } else {
            key = resolver.resolveSigningKey(jwsHeader, payload);
        }
        if (key == null) {
            String msg = "Cannot verify JWS signature: unable to locate signature verification key for JWS with header: " + jwsHeader;
            throw new UnsupportedJwtException(msg);
        }
        Provider provider = ProviderKey.getProvider(key, this.provider); // extract if necessary
        key = ProviderKey.getKey(key); // unwrap if necessary, MUST be called after ProviderKey.getProvider
        Assert.stateNotNull(key, "ProviderKey cannot be null."); //ProviderKey impl doesn't allow null
        if (key instanceof PrivateKey) {
            throw new InvalidKeyException(PRIV_KEY_VERIFY_MSG);
        }

        //re-create the jwt part without the signature.  This is what is needed for signature verification:
        String jwtWithoutSignature = tokenized.getProtected() + SEPARATOR_CHAR + tokenized.getPayload();

        byte[] data = jwtWithoutSignature.getBytes(StandardCharsets.US_ASCII);
        byte[] signature = decode(tokenized.getDigest(), "JWS signature");

        try {
            VerifySecureDigestRequest<Key> request =
                    new DefaultVerifySecureDigestRequest<>(data, provider, null, key, signature);
            if (!algorithm.verify(request)) {
                String msg = "JWT signature does not match locally computed signature. JWT validity cannot be " +
                        "asserted and should not be trusted.";
                throw new SignatureException(msg);
            }
        } catch (WeakKeyException e) {
            throw e;
        } catch (InvalidKeyException | IllegalArgumentException e) {
            String algId = algorithm.getId();
            String msg = "The parsed JWT indicates it was signed with the '" + algId + "' signature " +
                    "algorithm, but the provided " + key.getClass().getName() + " key may " +
                    "not be used to verify " + algId + " signatures.  Because the specified " +
                    "key reflects a specific and expected algorithm, and the JWT does not reflect " +
                    "this algorithm, it is likely that the JWT was not expected and therefore should not be " +
                    "trusted.  Another possibility is that the parser was provided the incorrect " +
                    "signature verification key, but this cannot be assumed for security reasons.";
            throw new UnsupportedJwtException(msg, e);
        }
    }

    @Override
    public Jwt<?, ?> parse(String compact) throws ExpiredJwtException, MalformedJwtException, SignatureException {

        Assert.hasText(compact, "JWT String cannot be null or empty.");

        final TokenizedJwt tokenized = jwtTokenizer.tokenize(compact);
        final String base64UrlHeader = tokenized.getProtected();
        if (!Strings.hasText(base64UrlHeader)) {
            String msg = "Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).";
            throw new MalformedJwtException(msg);
        }

        // =============== Header =================
        final byte[] headerBytes = decode(base64UrlHeader, "protected header");
        Map<String, ?> m = deserialize(headerBytes, "protected header");
        Header header;
        try {
            header = tokenized.createHeader(m);
        } catch (Exception e) {
            String msg = "Invalid protected header: " + e.getMessage();
            throw new MalformedJwtException(msg, e);
        }

        // https://tools.ietf.org/html/rfc7515#section-10.7 , second-to-last bullet point, note the use of 'always':
        //
        //   *  Require that the "alg" Header Parameter be carried in the JWS
        //      Protected Header.  (This is always the case when using the JWS
        //      Compact Serialization and is the approach taken by CMS [RFC6211].)
        //
        final String alg = Strings.clean(header.getAlgorithm());
        if (!Strings.hasText(alg)) {
            String msg = tokenized instanceof TokenizedJwe ? MISSING_JWE_ALG_MSG : MISSING_JWS_ALG_MSG;
            throw new MalformedJwtException(msg);
        }
        final boolean unsecured = Jwts.SIG.NONE.getId().equalsIgnoreCase(alg);

        final String base64UrlDigest = tokenized.getDigest();
        final boolean hasDigest = Strings.hasText(base64UrlDigest);
        if (unsecured) {
            if (tokenized instanceof TokenizedJwe) {
                throw new MalformedJwtException(JWE_NONE_MSG);
            }
            // Unsecured JWTs are disabled by default per the RFC:
            if (!enableUnsecured) {
                String msg = UNSECURED_DISABLED_MSG_PREFIX + header;
                throw new UnsupportedJwtException(msg);
            }
            if (hasDigest) {
                throw new MalformedJwtException(JWS_NONE_SIG_MISMATCH_MSG);
            }
        } else if (!hasDigest) { // something other than 'none'.  Must have a digest component:
            String fmt = tokenized instanceof TokenizedJwe ? MISSING_JWE_DIGEST_MSG_FMT : MISSING_JWS_DIGEST_MSG_FMT;
            String msg = String.format(fmt, alg);
            throw new MalformedJwtException(msg);
        }

        // =============== Payload =================
        byte[] payload = decode(tokenized.getPayload(), "payload");
        if (tokenized instanceof TokenizedJwe && Arrays.length(payload) == 0) { // Only JWS payload can be empty per https://github.com/jwtk/jjwt/pull/540
            String msg = "Compact JWE strings MUST always contain a payload (ciphertext).";
            throw new MalformedJwtException(msg);
        }

        byte[] iv = null;
        byte[] tag = null;
        if (tokenized instanceof TokenizedJwe) {

            TokenizedJwe tokenizedJwe = (TokenizedJwe) tokenized;
            JweHeader jweHeader = (JweHeader) header;

            byte[] cekBytes = Bytes.EMPTY; //ignored unless using an encrypted key algorithm
            String base64Url = tokenizedJwe.getEncryptedKey();
            if (Strings.hasText(base64Url)) {
                cekBytes = decode(base64Url, "JWE encrypted key");
                if (Arrays.length(cekBytes) == 0) {
                    String msg = "Compact JWE string represents an encrypted key, but the key is empty.";
                    throw new MalformedJwtException(msg);
                }
            }

            base64Url = tokenizedJwe.getIv();
            if (Strings.hasText(base64Url)) {
                iv = decode(base64Url, "JWE Initialization Vector");
            }
            if (Arrays.length(iv) == 0) {
                String msg = "Compact JWE strings must always contain an Initialization Vector.";
                throw new MalformedJwtException(msg);
            }

            // The AAD (Additional Authenticated Data) scheme for compact JWEs is to use the ASCII bytes of the
            // raw base64url text as the AAD, and NOT the base64url-decoded bytes per
            // https://www.rfc-editor.org/rfc/rfc7516.html#section-5.1, Step 14.
            final byte[] aad = base64UrlHeader.getBytes(StandardCharsets.US_ASCII);

            base64Url = base64UrlDigest;
            //guaranteed to be non-empty via the `alg` + digest check above:
            Assert.hasText(base64Url, "JWE AAD Authentication Tag cannot be null or empty.");
            tag = decode(base64Url, "JWE AAD Authentication Tag");
            if (Arrays.length(tag) == 0) {
                String msg = "Compact JWE strings must always contain an AAD Authentication Tag.";
                throw new MalformedJwtException(msg);
            }

            String enc = jweHeader.getEncryptionAlgorithm();
            if (!Strings.hasText(enc)) {
                throw new MalformedJwtException(MISSING_ENC_MSG);
            }
            final AeadAlgorithm encAlg = this.encAlgFn.apply(jweHeader);
            Assert.stateNotNull(encAlg, "JWE Encryption Algorithm cannot be null.");

            @SuppressWarnings("rawtypes") final KeyAlgorithm keyAlg = this.keyAlgFn.apply(jweHeader);
            Assert.stateNotNull(keyAlg, "JWE Key Algorithm cannot be null.");

            Key key = this.keyLocator.locate(jweHeader);
            if (key == null) {
                String msg = "Cannot decrypt JWE payload: unable to locate key for JWE with header: " + jweHeader;
                throw new UnsupportedJwtException(msg);
            }
            if (key instanceof PublicKey) {
                throw new InvalidKeyException(PUB_KEY_DECRYPT_MSG);
            }

            // extract key-specific provider if necessary;
            Provider provider = ProviderKey.getProvider(key, this.provider);
            key = ProviderKey.getKey(key); // this must be called after ProviderKey.getProvider
            DecryptionKeyRequest<Key> request =
                    new DefaultDecryptionKeyRequest<>(cekBytes, provider, null, jweHeader, encAlg, key);
            final SecretKey cek = keyAlg.getDecryptionKey(request);
            if (cek == null) {
                String msg = "The '" + keyAlg.getId() + "' JWE key algorithm did not return a decryption key. " +
                        "Unable to perform '" + encAlg.getId() + "' decryption.";
                throw new IllegalStateException(msg);
            }

            // During decryption, the available Provider applies to the KeyAlgorithm, not the AeadAlgorithm, mostly
            // because all JVMs support the standard AeadAlgorithms (especially with BouncyCastle in the classpath).
            // As such, the provider here is intentionally omitted (null):
            // TODO: add encProvider(Provider) builder method that applies to this request only?
            DecryptAeadRequest decryptRequest =
                    new DefaultAeadResult(null, null, payload, cek, aad, tag, iv);
            Message<byte[]> result = encAlg.decrypt(decryptRequest);
            payload = result.getPayload();

        } else if (hasDigest && this.signingKeyResolver == null) { //TODO: for 1.0, remove the == null check
            // not using a signing key resolver, so we can verify the signature before reading the payload, which is
            // always safer:
            verifySignature(tokenized, ((JwsHeader) header), alg, new LocatingKeyResolver(this.keyLocator), null, null);
        }

        CompressionAlgorithm compressionAlgorithm = zipAlgFn.apply(header);
        if (compressionAlgorithm != null) {
            if (unsecured && !enableUnsecuredDecompression) {
                String msg = String.format(UNPROTECTED_DECOMPRESSION_MSG, compressionAlgorithm.getId());
                throw new UnsupportedJwtException(msg);
            }
            payload = compressionAlgorithm.decompress(payload);
        }

        Claims claims = null;
        if (!hasContentType(header) // If there is a content type set, then the application using JJWT is expected
                //                     to convert the byte payload themselves based on this content type
                //                     https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
                //
                //                     "This parameter is ignored by JWS implementations; any processing of this
                //                      parameter is performed by the JWS application."
                //
                && isLikelyJson(payload)) { // likely to be json, parse it:
            Map<String, ?> claimsMap = deserialize(payload, "claims");
            try {
                claims = new DefaultClaims(claimsMap);
            } catch (Exception e) {
                String msg = "Invalid claims: " + e.getMessage();
                throw new MalformedJwtException(msg, e);
            }
        }

        Jwt<?, ?> jwt;
        Object body = claims != null ? claims : payload;
        if (header instanceof JweHeader) {
            jwt = new DefaultJwe<>((JweHeader) header, body, iv, tag);
        } else if (hasDigest) {
            JwsHeader jwsHeader = Assert.isInstanceOf(JwsHeader.class, header, "JwsHeader required.");
            jwt = new DefaultJws<>(jwsHeader, body, base64UrlDigest);
        } else {
            //noinspection rawtypes
            jwt = new DefaultJwt(header, body);
        }

        // =============== Signature =================
        if (hasDigest && signingKeyResolver != null) { // TODO: remove for 1.0
            // A SigningKeyResolver has been configured, and due to it's API, we have to verify the signature after
            // parsing the body.  This can be a security risk, so it needs to be removed before 1.0
            verifySignature(tokenized, ((JwsHeader) header), alg, this.signingKeyResolver, claims, payload);
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

                    long differenceMillis = nowTime - exp.getTime();

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

    private void validateExpectedClaims(Header header, Claims claims) {

        final Claims expected = expectedClaims.build();

        for (String expectedClaimName : expected.keySet()) {

            Object expectedClaimValue = normalize(expected.get(expectedClaimName));
            Object actualClaimValue = normalize(claims.get(expectedClaimName));

            if (expectedClaimValue instanceof Date) {
                try {
                    actualClaimValue = claims.get(expectedClaimName, Date.class);
                } catch (Exception e) {
                    String msg = "JWT Claim '" + expectedClaimName + "' was expected to be a Date, but its value " +
                            "cannot be converted to a Date using current heuristics.  Value: " + actualClaimValue;
                    throw new IncorrectClaimException(header, claims, expectedClaimName, expectedClaimValue, msg);
                }
            }

            if (actualClaimValue == null) {
                boolean collection = expectedClaimValue instanceof Collection;
                String msg = "Missing '" + expectedClaimName + "' claim. Expected value";
                if (collection) {
                    msg += "s: " + expectedClaimValue;
                } else {
                    msg += ": " + expectedClaimValue;
                }
                throw new MissingClaimException(header, claims, expectedClaimName, expectedClaimValue, msg);
            } else if (expectedClaimValue instanceof Collection) {
                Collection<?> expectedValues = (Collection<?>) expectedClaimValue;
                Collection<?> actualValues = actualClaimValue instanceof Collection ? (Collection<?>) actualClaimValue :
                        Collections.setOf(actualClaimValue);
                for (Object expectedValue : expectedValues) {
                    if (!Collections.contains(actualValues.iterator(), expectedValue)) {
                        String msg = String.format(MISSING_EXPECTED_CLAIM_VALUE_MESSAGE_TEMPLATE,
                                expectedValue, expectedClaimName, actualValues);
                        throw new IncorrectClaimException(header, claims, expectedClaimName, expectedClaimValue, msg);
                    }
                }
            } else if (!expectedClaimValue.equals(actualClaimValue)) {
                String msg = String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE,
                        expectedClaimName, expectedClaimValue, actualClaimValue);
                throw new IncorrectClaimException(header, claims, expectedClaimName, expectedClaimValue, msg);
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
            Object body = jws.getPayload();
            if (body instanceof Claims) {
                return handler.onClaimsJws((Jws<Claims>) jws);
            } else {
                return handler.onContentJws((Jws<byte[]>) jws);
            }
        } else if (jwt instanceof Jwe) {
            Jwe<?> jwe = (Jwe<?>) jwt;
            Object body = jwe.getPayload();
            if (body instanceof Claims) {
                return handler.onClaimsJwe((Jwe<Claims>) jwe);
            } else {
                return handler.onContentJwe((Jwe<byte[]>) jwe);
            }
        } else {
            Object body = jwt.getPayload();
            if (body instanceof Claims) {
                return handler.onClaimsJwt((Jwt<Header, Claims>) jwt);
            } else {
                return handler.onContentJwt((Jwt<Header, byte[]>) jwt);
            }
        }
    }

    @Override
    public Jwt<Header, byte[]> parseContentJwt(String compact) {
        return parse(compact, new JwtHandlerAdapter<Jwt<Header, byte[]>>() {
            @Override
            public Jwt<Header, byte[]> onContentJwt(Jwt<Header, byte[]> jwt) {
                return jwt;
            }
        });
    }

    @Override
    public Jwt<Header, Claims> parseClaimsJwt(String compact) {
        return parse(compact, new JwtHandlerAdapter<Jwt<Header, Claims>>() {
            @Override
            public Jwt<Header, Claims> onClaimsJwt(Jwt<Header, Claims> jwt) {
                return jwt;
            }
        });
    }

    @Override
    public Jws<byte[]> parseContentJws(String compact) {
        return parse(compact, new JwtHandlerAdapter<Jws<byte[]>>() {
            @Override
            public Jws<byte[]> onContentJws(Jws<byte[]> jws) {
                return jws;
            }
        });
    }

    @Override
    public Jws<Claims> parseClaimsJws(String compact) {
        return parse(compact, new JwtHandlerAdapter<Jws<Claims>>() {
            @Override
            public Jws<Claims> onClaimsJws(Jws<Claims> jws) {
                return jws;
            }
        });
    }

    @Override
    public Jwe<byte[]> parseContentJwe(String compact) throws JwtException {
        return parse(compact, new JwtHandlerAdapter<Jwe<byte[]>>() {
            @Override
            public Jwe<byte[]> onContentJwe(Jwe<byte[]> jwe) {
                return jwe;
            }
        });
    }

    @Override
    public Jwe<Claims> parseClaimsJwe(String compact) throws JwtException {
        return parse(compact, new JwtHandlerAdapter<Jwe<Claims>>() {
            @Override
            public Jwe<Claims> onClaimsJwe(Jwe<Claims> jwe) {
                return jwe;
            }
        });
    }

    protected byte[] decode(String base64UrlEncoded, String name) {
        try {
            return decoder.decode(base64UrlEncoded);
        } catch (DecodingException e) {
            String msg = "Invalid Base64Url " + name + ": " + base64UrlEncoded;
            throw new MalformedJwtException(msg, e);
        }
    }

    protected Map<String, ?> deserialize(byte[] bytes, final String name) {
        try {
            return deserializer.deserialize(bytes);
        } catch (MalformedJwtException | DeserializationException e) {
            String s = new String(bytes, StandardCharsets.UTF_8);
            throw new MalformedJwtException("Unable to read " + name + " JSON: " + s, e);
        }
    }
}

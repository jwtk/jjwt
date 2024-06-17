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
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.io.AbstractParser;
import io.jsonwebtoken.impl.io.BytesInputStream;
import io.jsonwebtoken.impl.io.CharSequenceReader;
import io.jsonwebtoken.impl.io.JsonObjectDeserializer;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.io.UncloseableInputStream;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.RedactedSupplier;
import io.jsonwebtoken.impl.security.DefaultDecryptAeadRequest;
import io.jsonwebtoken.impl.security.DefaultDecryptionKeyRequest;
import io.jsonwebtoken.impl.security.DefaultVerifySecureDigestRequest;
import io.jsonwebtoken.impl.security.LocatingKeyResolver;
import io.jsonwebtoken.impl.security.ProviderKey;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptAeadRequest;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.Reader;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@SuppressWarnings("unchecked")
public class DefaultJwtParser extends AbstractParser<Jwt<?, ?>> implements JwtParser {

    static final char SEPARATOR_CHAR = '.';

    private static final JwtTokenizer jwtTokenizer = new JwtTokenizer();

    static final String PRIV_KEY_VERIFY_MSG = "PrivateKeys may not be used to verify digital signatures. " +
            "PrivateKeys are used to sign, and PublicKeys are used to verify.";

    static final String PUB_KEY_DECRYPT_MSG = "PublicKeys may not be used to decrypt data. PublicKeys are " +
            "used to encrypt, and PrivateKeys are used to decrypt.";

    public static final String INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE = "Expected %s claim to be: %s, but was: %s.";

    public static final String MISSING_EXPECTED_CLAIM_VALUE_MESSAGE_TEMPLATE =
            "Missing expected '%s' value in '%s' claim %s.";

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
            "allow them to be parsed, call the JwtParserBuilder.unsecured() method, but please read the " +
            "security considerations covered in that method's JavaDoc before doing so. Header: ";

    private static final String CRIT_UNSECURED_MSG = "Unsecured JWSs (those with an " + DefaultHeader.ALGORITHM +
            " header value of '" + Jwts.SIG.NONE.getId() + "') may not use the " + DefaultProtectedHeader.CRIT +
            " header parameter per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11 (\"the [crit] Header " +
            "Parameter MUST be integrity protected; therefore, it MUST occur only within [a] JWS Protected Header)\"." +
            " Header: %s";

    private static final String CRIT_MISSING_MSG = "Protected Header " +
            DefaultProtectedHeader.CRIT + " set references header name '%s', but the header does not contain an " +
            "associated '%s' header parameter as required by " +
            "https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11. Header: %s";

    private static final String CRIT_UNSUPPORTED_MSG = "Protected Header " + DefaultProtectedHeader.CRIT +
            " set references unsupported header name '%s'. Application developers expecting to support a JWT " +
            "extension using header '%s' in their application code must indicate it " +
            "is supported by using the JwtParserBuilder.critical method. Header: %s";

    private static final String JWE_NONE_MSG = "JWEs do not support key management " + DefaultHeader.ALGORITHM +
            " header value '" + Jwts.SIG.NONE.getId() + "' per " +
            "https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1";

    private static final String JWS_NONE_SIG_MISMATCH_MSG = "The JWS header references signature algorithm '" +
            Jwts.SIG.NONE.getId() + "' yet the compact JWS string contains a signature. This is not permitted " +
            "per https://tools.ietf.org/html/rfc7518#section-3.6.";

    private static final String B64_MISSING_PAYLOAD = "Unable to verify JWS signature: the parser has encountered an " +
            "Unencoded Payload JWS with detached payload, but the detached payload value required for signature " +
            "verification has not been provided. If you expect to receive and parse Unencoded Payload JWSs in your " +
            "application, the overloaded JwtParser.parseSignedContent or JwtParser.parseSignedClaims methods that " +
            "accept a byte[] or InputStream must be used for these kinds of JWSs. Header: %s";

    private static final String B64_DECOMPRESSION_MSG = "The JWT header references compression algorithm " +
            "'%s', but payload decompression for Unencoded JWSs (those with an " + DefaultJwsHeader.B64 +
            " header value of false) that rely on a SigningKeyResolver are disallowed " +
            "by default to protect against [Denial of Service attacks](" +
            "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf).  If you " +
            "wish to enable Unencoded JWS payload decompression, configure the JwtParserBuilder." +
            "keyLocator(Locator) and do not configure a SigningKeyResolver.";

    private static final String UNPROTECTED_DECOMPRESSION_MSG = "The JWT header references compression algorithm " +
            "'%s', but payload decompression for Unprotected JWTs (those with an " + DefaultHeader.ALGORITHM +
            " header value of '" + Jwts.SIG.NONE.getId() + "') or Unencoded JWSs (those with a " +
            DefaultJwsHeader.B64 + " header value of false) that also rely on a SigningKeyResolver are disallowed " +
            "by default to protect against [Denial of Service attacks](" +
            "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-pellegrino.pdf).  If you " +
            "wish to enable Unsecure JWS or Unencoded JWS payload decompression, call the JwtParserBuilder." +
            "unsecuredDecompression() method, but please read the security considerations covered in that " +
            "method's JavaDoc before doing so.";

    private final Provider provider;

    @SuppressWarnings("deprecation")
    private final SigningKeyResolver signingKeyResolver;

    private final boolean unsecured;

    private final boolean unsecuredDecompression;

    private final Function<JwsHeader, SecureDigestAlgorithm<?, ?>> sigAlgs;

    private final Function<JweHeader, AeadAlgorithm> encAlgs;

    private final Function<JweHeader, KeyAlgorithm<?, ?>> keyAlgs;

    private final Function<Header, CompressionAlgorithm> zipAlgs;

    private final Locator<? extends Key> keyLocator;

    private final Decoder<InputStream, InputStream> decoder;

    private final Deserializer<Map<String, ?>> deserializer;

    private final ClaimsBuilder expectedClaims;

    private final Clock clock;

    private final Set<String> critical;

    private final long allowedClockSkewMillis;

    //SigningKeyResolver will be removed for 1.0:
    @SuppressWarnings("deprecation")
    DefaultJwtParser(Provider provider,
                     SigningKeyResolver signingKeyResolver,
                     boolean unsecured,
                     boolean unsecuredDecompression,
                     Locator<? extends Key> keyLocator,
                     Clock clock,
                     Set<String> critical,
                     long allowedClockSkewMillis,
                     DefaultClaims expectedClaims,
                     Decoder<InputStream, InputStream> base64UrlDecoder,
                     Deserializer<Map<String, ?>> deserializer,
                     CompressionCodecResolver compressionCodecResolver,
                     Registry<String, CompressionAlgorithm> zipAlgs,
                     Registry<String, SecureDigestAlgorithm<?, ?>> sigAlgs,
                     Registry<String, KeyAlgorithm<?, ?>> keyAlgs,
                     Registry<String, AeadAlgorithm> encAlgs) {
        this.provider = provider;
        this.unsecured = unsecured;
        this.unsecuredDecompression = unsecuredDecompression;
        this.signingKeyResolver = signingKeyResolver;
        this.keyLocator = Assert.notNull(keyLocator, "Key Locator cannot be null.");
        this.clock = Assert.notNull(clock, "Clock cannot be null.");
        this.critical = Collections.nullSafe(critical);
        this.allowedClockSkewMillis = allowedClockSkewMillis;
        this.expectedClaims = Jwts.claims().add(expectedClaims);
        this.decoder = Assert.notNull(base64UrlDecoder, "base64UrlDecoder cannot be null.");
        this.deserializer = Assert.notNull(deserializer, "JSON Deserializer cannot be null.");
        this.sigAlgs = new IdLocator<>(DefaultHeader.ALGORITHM, sigAlgs, MISSING_JWS_ALG_MSG);
        this.keyAlgs = new IdLocator<>(DefaultHeader.ALGORITHM, keyAlgs, MISSING_JWE_ALG_MSG);
        this.encAlgs = new IdLocator<>(DefaultJweHeader.ENCRYPTION_ALGORITHM, encAlgs, MISSING_ENC_MSG);
        this.zipAlgs = compressionCodecResolver != null ? new CompressionCodecLocator(compressionCodecResolver) :
                new IdLocator<>(DefaultHeader.COMPRESSION_ALGORITHM, zipAlgs, null);
    }

    @Override
    public boolean isSigned(CharSequence compact) {
        if (!Strings.hasText(compact)) {
            return false;
        }
        try {
            final TokenizedJwt tokenized = jwtTokenizer.tokenize(new CharSequenceReader(compact));
            return !(tokenized instanceof TokenizedJwe) && Strings.hasText(tokenized.getDigest());
        } catch (MalformedJwtException e) {
            return false;
        }
    }

    private static boolean hasContentType(Header header) {
        return header != null && Strings.hasText(header.getContentType());
    }

    private byte[] verifySignature(final TokenizedJwt tokenized, final JwsHeader jwsHeader, final String alg,
                                   @SuppressWarnings("deprecation") SigningKeyResolver resolver, Claims claims, Payload payload) {

        Assert.notNull(resolver, "SigningKeyResolver instance cannot be null.");

        SecureDigestAlgorithm<?, Key> algorithm;
        try {
            algorithm = (SecureDigestAlgorithm<?, Key>) sigAlgs.apply(jwsHeader);
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
            key = resolver.resolveSigningKey(jwsHeader, payload.getBytes());
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

        final byte[] signature = decode(tokenized.getDigest(), "JWS signature");

        //re-create the jwt part without the signature.  This is what is needed for signature verification:
        InputStream payloadStream = null;
        InputStream verificationInput;
        if (jwsHeader.isPayloadEncoded()) {
            int len = tokenized.getProtected().length() + 1 + tokenized.getPayload().length();
            CharBuffer cb = CharBuffer.allocate(len);
            cb.put(Strings.wrap(tokenized.getProtected()));
            cb.put(SEPARATOR_CHAR);
            cb.put(Strings.wrap(tokenized.getPayload()));
            cb.rewind();
            ByteBuffer bb = StandardCharsets.US_ASCII.encode(cb);
            bb.rewind();
            byte[] data = new byte[bb.remaining()];
            bb.get(data);
            verificationInput = Streams.of(data);
        } else { // b64 extension
            ByteBuffer headerBuf = StandardCharsets.US_ASCII.encode(Strings.wrap(tokenized.getProtected()));
            headerBuf.rewind();
            ByteBuffer buf = ByteBuffer.allocate(headerBuf.remaining() + 1);
            buf.put(headerBuf);
            buf.put((byte) SEPARATOR_CHAR);
            buf.rewind();
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            InputStream prefixStream = Streams.of(data);
            payloadStream = payload.toInputStream();
            // We wrap the payloadStream here in an UncloseableInputStream to prevent the SequenceInputStream from
            // closing it since we'll need to rewind/reset it if decompression is enabled
            verificationInput = new SequenceInputStream(prefixStream, new UncloseableInputStream(payloadStream));
        }

        try {
            VerifySecureDigestRequest<Key> request =
                    new DefaultVerifySecureDigestRequest<>(verificationInput, provider, null, key, signature);
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
        } finally {
            Streams.reset(payloadStream);
        }

        return signature;
    }

    @Override
    public Jwt<?, ?> parse(Reader reader) {
        Assert.notNull(reader, "Reader cannot be null.");
        return parse(reader, Payload.EMPTY);
    }

    private Jwt<?, ?> parse(Reader compact, Payload unencodedPayload) {

        Assert.notNull(compact, "Compact reader cannot be null.");
        Assert.stateNotNull(unencodedPayload, "internal error: unencodedPayload is null.");

        final TokenizedJwt tokenized = jwtTokenizer.tokenize(compact);
        final CharSequence base64UrlHeader = tokenized.getProtected();
        if (!Strings.hasText(base64UrlHeader)) {
            String msg = "Compact JWT strings MUST always have a Base64Url protected header per " +
                    "https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).";
            throw new MalformedJwtException(msg);
        }

        // =============== Header =================
        final byte[] headerBytes = decode(base64UrlHeader, "protected header");
        Map<String, ?> m = deserialize(Streams.of(headerBytes), "protected header");
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

        final CharSequence base64UrlDigest = tokenized.getDigest();
        final boolean hasDigest = Strings.hasText(base64UrlDigest);
        if (unsecured) {
            if (tokenized instanceof TokenizedJwe) {
                throw new MalformedJwtException(JWE_NONE_MSG);
            }
            // Unsecured JWTs are disabled by default per the RFC:
            if (!this.unsecured) {
                String msg = UNSECURED_DISABLED_MSG_PREFIX + header;
                throw new UnsupportedJwtException(msg);
            }
            if (hasDigest) {
                throw new MalformedJwtException(JWS_NONE_SIG_MISMATCH_MSG);
            }
            if (header.containsKey(DefaultProtectedHeader.CRIT.getId())) {
                String msg = String.format(CRIT_UNSECURED_MSG, header);
                throw new MalformedJwtException(msg);
            }
        } else if (!hasDigest) { // something other than 'none'.  Must have a digest component:
            String fmt = tokenized instanceof TokenizedJwe ? MISSING_JWE_DIGEST_MSG_FMT : MISSING_JWS_DIGEST_MSG_FMT;
            String msg = String.format(fmt, alg);
            throw new MalformedJwtException(msg);
        }
        // ----- crit assertions -----
        if (header instanceof ProtectedHeader) {
            Set<String> crit = Collections.nullSafe(((ProtectedHeader) header).getCritical());
            Set<String> supportedCrit = this.critical;
            String b64Id = DefaultJwsHeader.B64.getId();
            if (!unencodedPayload.isEmpty() && !this.critical.contains(b64Id)) {
                // The application developer explicitly indicates they're using a B64 payload, so
                // ensure that the B64 crit header is supported, even if they forgot to configure it on the
                // parser builder:
                supportedCrit = new LinkedHashSet<>(Collections.size(this.critical) + 1);
                supportedCrit.add(DefaultJwsHeader.B64.getId());
                supportedCrit.addAll(this.critical);
            }
            // assert any values per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11:
            for (String name : crit) {
                if (!header.containsKey(name)) {
                    String msg = String.format(CRIT_MISSING_MSG, name, name, header);
                    throw new MalformedJwtException(msg);
                }
                if (!supportedCrit.contains(name)) {
                    String msg = String.format(CRIT_UNSUPPORTED_MSG, name, name, header);
                    throw new UnsupportedJwtException(msg);
                }
            }
        }

        // =============== Payload =================
        final CharSequence payloadToken = tokenized.getPayload();
        Payload payload;
        boolean integrityVerified = false; // only true after successful signature verification or AEAD decryption

        // check if b64 extension enabled:
        final boolean payloadBase64UrlEncoded = !(header instanceof JwsHeader) || ((JwsHeader) header).isPayloadEncoded();
        if (payloadBase64UrlEncoded) {
            // standard encoding, so decode it:
            byte[] data = decode(tokenized.getPayload(), "payload");
            payload = new Payload(data, header.getContentType());
        } else {
            // The JWT uses the b64 extension, and we already know the parser supports that extension at this point
            // in the code execution path because of the ----- crit ----- assertions section above as well as the
            // (JwsHeader).isPayloadEncoded() check
            if (Strings.hasText(payloadToken)) {
                // we need to verify what was in the token, otherwise it'd be a security issue if we ignored it
                // and assumed the (likely safe) unencodedPayload value instead:
                payload = new Payload(payloadToken, header.getContentType());
            } else {
                //no payload token (a detached payload), so we need to ensure that they've specified the payload value:
                if (unencodedPayload.isEmpty()) {
                    String msg = String.format(B64_MISSING_PAYLOAD, header);
                    throw new SignatureException(msg);
                }
                // otherwise, use the specified payload:
                payload = unencodedPayload;
            }
        }

        if (tokenized instanceof TokenizedJwe && payload.isEmpty()) {
            // Only JWS payload can be empty per https://github.com/jwtk/jjwt/pull/540
            String msg = "Compact JWE strings MUST always contain a payload (ciphertext).";
            throw new MalformedJwtException(msg);
        }

        byte[] iv = null;
        byte[] digest = null; // either JWE AEAD tag or JWS signature after Base64Url-decoding
        if (tokenized instanceof TokenizedJwe) {

            TokenizedJwe tokenizedJwe = (TokenizedJwe) tokenized;
            JweHeader jweHeader = Assert.stateIsInstance(JweHeader.class, header, "Not a JweHeader. ");

            byte[] cekBytes = Bytes.EMPTY; //ignored unless using an encrypted key algorithm
            CharSequence base64Url = tokenizedJwe.getEncryptedKey();
            if (Strings.hasText(base64Url)) {
                cekBytes = decode(base64Url, "JWE encrypted key");
                if (Bytes.isEmpty(cekBytes)) {
                    String msg = "Compact JWE string represents an encrypted key, but the key is empty.";
                    throw new MalformedJwtException(msg);
                }
            }

            base64Url = tokenizedJwe.getIv();
            if (Strings.hasText(base64Url)) {
                iv = decode(base64Url, "JWE Initialization Vector");
            }
            if (Bytes.isEmpty(iv)) {
                String msg = "Compact JWE strings must always contain an Initialization Vector.";
                throw new MalformedJwtException(msg);
            }

            // The AAD (Additional Authenticated Data) scheme for compact JWEs is to use the ASCII bytes of the
            // raw base64url text as the AAD, and NOT the base64url-decoded bytes per
            // https://www.rfc-editor.org/rfc/rfc7516.html#section-5.1, Step 14.
            ByteBuffer buf = StandardCharsets.US_ASCII.encode(Strings.wrap(base64UrlHeader));
            final byte[] aadBytes = new byte[buf.remaining()];
            buf.get(aadBytes);
            InputStream aad = Streams.of(aadBytes);

            base64Url = base64UrlDigest;
            //guaranteed to be non-empty via the `alg` + digest check above:
            Assert.hasText(base64Url, "JWE AAD Authentication Tag cannot be null or empty.");
            digest = decode(base64Url, "JWE AAD Authentication Tag");
            if (Bytes.isEmpty(digest)) {
                String msg = "Compact JWE strings must always contain an AAD Authentication Tag.";
                throw new MalformedJwtException(msg);
            }

            String enc = jweHeader.getEncryptionAlgorithm();
            if (!Strings.hasText(enc)) {
                throw new MalformedJwtException(MISSING_ENC_MSG);
            }
            final AeadAlgorithm encAlg = this.encAlgs.apply(jweHeader);
            Assert.stateNotNull(encAlg, "JWE Encryption Algorithm cannot be null.");

            @SuppressWarnings("rawtypes") final KeyAlgorithm keyAlg = this.keyAlgs.apply(jweHeader);
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
            InputStream ciphertext = payload.toInputStream();
            ByteArrayOutputStream plaintext = new ByteArrayOutputStream(8192);
            DecryptAeadRequest dreq = new DefaultDecryptAeadRequest(ciphertext, cek, aad, iv, digest);
            encAlg.decrypt(dreq, plaintext);
            payload = new Payload(plaintext.toByteArray(), header.getContentType());

            integrityVerified = true; // AEAD performs integrity verification, so no exception = verified

        } else if (hasDigest && this.signingKeyResolver == null) { //TODO: for 1.0, remove the == null check
            // not using a signing key resolver, so we can verify the signature before reading the payload, which is
            // always safer:
            JwsHeader jwsHeader = Assert.stateIsInstance(JwsHeader.class, header, "Not a JwsHeader. ");
            digest = verifySignature(tokenized, jwsHeader, alg, new LocatingKeyResolver(this.keyLocator), null, payload);
            integrityVerified = true; // no exception means signature verified
        }

        final CompressionAlgorithm compressionAlgorithm = zipAlgs.apply(header);
        if (compressionAlgorithm != null) {
            if (!integrityVerified) {
                if (!payloadBase64UrlEncoded) {
                    String msg = String.format(B64_DECOMPRESSION_MSG, compressionAlgorithm.getId());
                    throw new UnsupportedJwtException(msg);
                } else if (!unsecuredDecompression) {
                    String msg = String.format(UNPROTECTED_DECOMPRESSION_MSG, compressionAlgorithm.getId());
                    throw new UnsupportedJwtException(msg);
                }
            }
            payload = payload.decompress(compressionAlgorithm);
        }

        Claims claims = null;
        byte[] payloadBytes = payload.getBytes();
        if (payload.isConsumable()) {
            InputStream in = null;
            try {
                in = payload.toInputStream();

                if (!hasContentType(header)) {   // If there is a content type set, then the application using JJWT is expected
                    //                          to convert the byte payload themselves based on this content type
                    //                          https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 :
                    //
                    //                          "This parameter is ignored by JWS implementations; any processing of this
                    //                          parameter is performed by the JWS application."
                    //
                    Map<String, ?> claimsMap = null;
                    try {
                        // if deserialization fails, we'll need to rewind to convert to a byte array.  So if
                        // mark/reset isn't possible, we'll need to buffer:
                        if (!in.markSupported()) {
                            in = new BufferedInputStream(in);
                            in.mark(0);
                        }
                        claimsMap = deserialize(new UncloseableInputStream(in) /* Don't close in case we need to rewind */, "claims");
                    } catch (DeserializationException |
                             MalformedJwtException ignored) { // not JSON, treat it as a byte[]
//                String msg = "Invalid claims: " + e.getMessage();
//                throw new MalformedJwtException(msg, e);
                    } finally {
                        Streams.reset(in);
                    }
                    if (claimsMap != null) {
                        try {
                            claims = new DefaultClaims(claimsMap);
                        } catch (Throwable t) {
                            String msg = "Invalid claims: " + t.getMessage();
                            throw new MalformedJwtException(msg);
                        }
                    }
                }
                if (claims == null) {
                    // consumable, but not claims, so convert to byte array:
                    payloadBytes = Streams.bytes(in, "Unable to convert payload to byte array.");
                }
            } finally { // always ensure closed per https://github.com/jwtk/jjwt/issues/949
                Objects.nullSafeClose(in);
            }
        }

        // =============== Post-SKR Signature Check =================
        if (hasDigest && signingKeyResolver != null) { // TODO: remove for 1.0
            // A SigningKeyResolver has been configured, and due to it's API, we have to verify the signature after
            // parsing the body.  This can be a security risk, so it needs to be removed before 1.0
            JwsHeader jwsHeader = Assert.stateIsInstance(JwsHeader.class, header, "Not a JwsHeader. ");
            digest = verifySignature(tokenized, jwsHeader, alg, this.signingKeyResolver, claims, payload);
            //noinspection UnusedAssignment
            integrityVerified = true; // no exception means verified successfully
        }

        Jwt<?, ?> jwt;
        Object body = claims != null ? claims : payloadBytes;
        if (header instanceof JweHeader) {
            jwt = new DefaultJwe<>((JweHeader) header, body, iv, digest);
        } else if (hasDigest) {
            JwsHeader jwsHeader = Assert.isInstanceOf(JwsHeader.class, header, "JwsHeader required.");
            jwt = new DefaultJws<>(jwsHeader, body, digest, base64UrlDigest.toString());
        } else {
            //noinspection rawtypes
            jwt = new DefaultJwt(header, body);
        }

        final boolean allowSkew = this.allowedClockSkewMillis > 0;

        //since 0.3:
        if (claims != null) {

            final Date now = this.clock.now();
            long nowTime = now.getTime();

            // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
            // token MUST NOT be accepted on or after any specified exp time:
            Date exp = claims.getExpiration();
            if (exp != null) {

                long maxTime = nowTime - this.allowedClockSkewMillis;
                Date max = allowSkew ? new Date(maxTime) : now;
                if (max.after(exp)) {
                    String expVal = DateFormats.formatIso8601(exp, true);
                    String nowVal = DateFormats.formatIso8601(now, true);

                    long differenceMillis = nowTime - exp.getTime();

                    String msg = "JWT expired " + differenceMillis + " milliseconds ago at " + expVal + ". " +
                            "Current time: " + nowVal + ". Allowed clock skew: " +
                            this.allowedClockSkewMillis + " milliseconds.";
                    throw new ExpiredJwtException(header, claims, msg);
                }
            }

            // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5
            // token MUST NOT be accepted before any specified nbf time:
            Date nbf = claims.getNotBefore();
            if (nbf != null) {

                long minTime = nowTime + this.allowedClockSkewMillis;
                Date min = allowSkew ? new Date(minTime) : now;
                if (min.before(nbf)) {
                    String nbfVal = DateFormats.formatIso8601(nbf, true);
                    String nowVal = DateFormats.formatIso8601(now, true);

                    long differenceMillis = nbf.getTime() - nowTime;

                    String msg = "JWT early by " + differenceMillis + " milliseconds before " + nbfVal +
                            ". Current time: " + nowVal + ". Allowed clock skew: " +
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

    @SuppressWarnings("deprecation")
    @Override
    public <T> T parse(CharSequence compact, JwtHandler<T> handler) {
        return parse(compact, Payload.EMPTY).accept(handler);
    }

    private Jwt<?, ?> parse(CharSequence compact, Payload unencodedPayload) {
        Assert.hasText(compact, "JWT String argument cannot be null or empty.");
        return parse(new CharSequenceReader(compact), unencodedPayload);
    }

    @Override
    public Jwt<Header, byte[]> parseContentJwt(CharSequence jwt) {
        return parse(jwt).accept(Jwt.UNSECURED_CONTENT);
    }

    @Override
    public Jwt<Header, Claims> parseClaimsJwt(CharSequence jwt) {
        return parse(jwt).accept(Jwt.UNSECURED_CLAIMS);
    }

    @Override
    public Jws<byte[]> parseContentJws(CharSequence jws) {
        return parseSignedContent(jws);
    }

    @Override
    public Jws<Claims> parseClaimsJws(CharSequence jws) {
        return parseSignedClaims(jws);
    }

    @Override
    public Jwt<Header, byte[]> parseUnsecuredContent(CharSequence jwt) throws JwtException, IllegalArgumentException {
        return parse(jwt).accept(Jwt.UNSECURED_CONTENT);
    }

    @Override
    public Jwt<Header, Claims> parseUnsecuredClaims(CharSequence jwt) throws JwtException, IllegalArgumentException {
        return parse(jwt).accept(Jwt.UNSECURED_CLAIMS);
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence compact) {
        return parse(compact).accept(Jws.CONTENT);
    }

    private Jws<byte[]> parseSignedContent(CharSequence jws, Payload unencodedPayload) {
        return parse(jws, unencodedPayload).accept(Jws.CONTENT);
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence compact) {
        return parse(compact).accept(Jws.CLAIMS);
    }

    private Jws<Claims> parseSignedClaims(CharSequence jws, Payload unencodedPayload) {
        unencodedPayload.setClaimsExpected(true);
        return parse(jws, unencodedPayload).accept(Jws.CLAIMS);
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence jws, byte[] unencodedPayload) {
        Assert.notEmpty(unencodedPayload, "unencodedPayload argument cannot be null or empty.");
        return parseSignedContent(jws, new Payload(unencodedPayload, null));
    }

    private static Payload payloadFor(InputStream in) {
        if (in instanceof BytesInputStream) {
            byte[] data = Streams.bytes(in, "Unable to obtain payload InputStream bytes.");
            return new Payload(data, null);
        }
        //if (in.markSupported()) in.mark(0);
        return new Payload(in, null);
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence jws, InputStream unencodedPayload) {
        Assert.notNull(unencodedPayload, "unencodedPayload InputStream cannot be null.");
        return parseSignedContent(jws, payloadFor(unencodedPayload));
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence jws, byte[] unencodedPayload) {
        Assert.notEmpty(unencodedPayload, "unencodedPayload argument cannot be null or empty.");
        return parseSignedClaims(jws, new Payload(unencodedPayload, null));
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence jws, InputStream unencodedPayload) {
        Assert.notNull(unencodedPayload, "unencodedPayload InputStream cannot be null.");
        byte[] bytes = Streams.bytes(unencodedPayload,
                "Unable to obtain Claims bytes from unencodedPayload InputStream");
        return parseSignedClaims(jws, new Payload(bytes, null));
    }

    @Override
    public Jwe<byte[]> parseEncryptedContent(CharSequence compact) throws JwtException {
        return parse(compact).accept(Jwe.CONTENT);
    }

    @Override
    public Jwe<Claims> parseEncryptedClaims(CharSequence compact) throws JwtException {
        return parse(compact).accept(Jwe.CLAIMS);
    }

    protected byte[] decode(CharSequence base64UrlEncoded, String name) {
        try {
            InputStream decoding = this.decoder.decode(Streams.of(Strings.utf8(base64UrlEncoded)));
            return Streams.bytes(decoding, "Unable to Base64Url-decode input.");
        } catch (Throwable t) {
            // Don't disclose potentially-sensitive information per https://github.com/jwtk/jjwt/issues/824:
            String value = "payload".equals(name) ? RedactedSupplier.REDACTED_VALUE : base64UrlEncoded.toString();
            String msg = "Invalid Base64Url " + name + ": " + value;
            throw new MalformedJwtException(msg, t);
        }
    }

    protected Map<String, ?> deserialize(InputStream in, final String name) {
        try {
            Reader reader = Streams.reader(in);
            JsonObjectDeserializer deserializer = new JsonObjectDeserializer(this.deserializer, name);
            return deserializer.apply(reader);
        } finally {
            Objects.nullSafeClose(in);
        }
    }
}

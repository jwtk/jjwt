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
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CompactMediaTypeIdConverter;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.DefaultAeadRequest;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.DefaultSecureRequest;
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

public class DefaultJwtBuilder implements JwtBuilder {

    public static final String PUB_KEY_SIGN_MSG = "PublicKeys may not be used to create digital signatures. " + "Only PrivateKeys may be used to create digital signatures, and PublicKeys are used to verify " + "digital signatures.";

    protected Provider provider;
    protected SecureRandom secureRandom;

    private final DefaultJwtBuilderHeader headerBuilder = new DefaultJwtBuilderHeader(this);

    private final ClaimsBuilder claimsBuilder = new DefaultClaimsBuilder();

    protected byte[] content;

    private SecureDigestAlgorithm<Key, ?> sigAlg = Jwts.SIG.NONE;
    private Function<SecureRequest<byte[], Key>, byte[]> signFunction;

    private AeadAlgorithm enc; // MUST be Symmetric AEAD per https://tools.ietf.org/html/rfc7516#section-4.1.2
    private Function<AeadRequest, AeadResult> encFunction;

    private KeyAlgorithm<Key, ?> keyAlg;
    private Function<KeyRequest<Key>, KeyResult> keyAlgFunction;

    private Key key;

    protected Serializer<Map<String, ?>> serializer;
    protected Function<Map<String, ?>, byte[]> headerSerializer;
    protected Function<Map<String, ?>, byte[]> claimsSerializer;

    protected Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
    protected CompressionCodec compressionCodec;

    @Override
    public JwtBuilder.Header header() {
        return this.headerBuilder;
    }

    @Override
    public JwtBuilder setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public JwtBuilder setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    protected <I, O> Function<I, O> wrap(Function<I, O> fn, String fmt, Object... args) {
        return Functions.wrap(fn, SecurityException.class, fmt, args);
    }

    protected Function<Map<String, ?>, byte[]> wrap(final Serializer<Map<String, ?>> serializer, final String which) {
        return new Function<Map<String, ?>, byte[]>() {
            @Override
            public byte[] apply(Map<String, ?> stringMap) {
                try {
                    return serializer.serialize(stringMap);
                } catch (Exception e) {
                    String fmt = String.format("Unable to serialize %s to JSON.", which);
                    String msg = fmt + " Cause: " + e.getMessage();
                    throw new SerializationException(msg);
                }
            }
        };
    }

    @Override
    public JwtBuilder serializeToJsonWith(final Serializer<Map<String, ?>> serializer) {
        Assert.notNull(serializer, "Serializer cannot be null.");
        this.serializer = serializer;
        this.headerSerializer = wrap(serializer, "header");
        this.claimsSerializer = wrap(serializer, "claims");
        return this;
    }

    @Override
    public JwtBuilder base64UrlEncodeWith(Encoder<byte[], String> base64UrlEncoder) {
        Assert.notNull(base64UrlEncoder, "base64UrlEncoder cannot be null.");
        this.base64UrlEncoder = base64UrlEncoder;
        return this;
    }

    @Override
    public JwtBuilder setHeader(Map<String, ?> map) {
        this.headerBuilder.clear();
        this.headerBuilder.putAll(map);
        return this;
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, ?> params) {
        this.headerBuilder.putAll(params);
        return this;
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        this.headerBuilder.put(name, value);
        return this;
    }

    @SuppressWarnings("unchecked") // TODO: remove for 1.0
    protected static <K extends Key> SecureDigestAlgorithm<K, ?> forSigningKey(K key) {
        @SuppressWarnings("deprecation") io.jsonwebtoken.SignatureAlgorithm alg = io.jsonwebtoken.SignatureAlgorithm.forSigningKey(key);
        return (SecureDigestAlgorithm<K, ?>) Jwts.SIG.get().forKey(alg.getValue());
    }

    @Override
    public JwtBuilder signWith(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        SecureDigestAlgorithm<Key, ?> alg = forSigningKey(key); // https://github.com/jwtk/jjwt/issues/381
        return signWith(key, alg);
    }

    @Override
    public <K extends Key> JwtBuilder signWith(K key, final SecureDigestAlgorithm<? super K, ?> alg) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        if (key instanceof PublicKey) { // it's always wrong to try to create signatures with PublicKeys:
            throw new IllegalArgumentException(PUB_KEY_SIGN_MSG);
        }
        // Implementation note:  Ordinarily Passwords should not be used to create secure digests because they usually
        // lack the length or entropy necessary for secure cryptographic operations, and are prone to misuse.
        // However, we DO NOT prevent them as arguments here (like the above PublicKey check) because
        // it is conceivable that a custom SecureDigestAlgorithm implementation would allow Password instances
        // so that it might perform its own internal key-derivation logic producing a key that is then used to create a
        // secure hash.
        //
        // Even so, a fallback safety check is that JJWT's only out-of-the-box Password implementation
        // (io.jsonwebtoken.impl.security.PasswordSpec) explicitly forbids calls to password.getEncoded() in all
        // scenarios to avoid potential misuse, so a digest algorithm implementation would explicitly need to avoid
        // this by calling toCharArray() instead.
        //
        // TLDR; the digest algorithm implementation has the final say whether a password instance is valid

        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        String id = Assert.hasText(alg.getId(), "SignatureAlgorithm id cannot be null or empty.");
        if (Jwts.SIG.NONE.getId().equalsIgnoreCase(id)) {
            String msg = "The 'none' JWS algorithm cannot be used to sign JWTs.";
            throw new IllegalArgumentException(msg);
        }
        this.key = key;
        //noinspection unchecked
        this.sigAlg = (SecureDigestAlgorithm<Key, ?>) alg;
        this.signFunction = Functions.wrap(new Function<SecureRequest<byte[], Key>, byte[]>() {
            @Override
            public byte[] apply(SecureRequest<byte[], Key> request) {
                return sigAlg.digest(request);
            }
        }, SignatureException.class, "Unable to compute %s signature.", id);
        return this;
    }

    @SuppressWarnings({"deprecation", "unchecked"}) // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(Key key, io.jsonwebtoken.SignatureAlgorithm alg) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        alg.assertValidSigningKey(key); //since 0.10.0 for https://github.com/jwtk/jjwt/issues/334
        return signWith(key, (SecureDigestAlgorithm<? super Key, ?>) Jwts.SIG.get().forKey(alg.getValue()));
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(io.jsonwebtoken.SignatureAlgorithm alg, byte[] secretKeyBytes) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notEmpty(secretKeyBytes, "secret key byte array cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        SecretKey key = new SecretKeySpec(secretKeyBytes, alg.getJcaName());
        return signWith(key, alg);
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(io.jsonwebtoken.SignatureAlgorithm alg, String base64EncodedSecretKey) throws InvalidKeyException {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return signWith(alg, bytes);
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(io.jsonwebtoken.SignatureAlgorithm alg, Key key) {
        return signWith(key, alg);
    }

    @Override
    public JwtBuilder encryptWith(SecretKey key, AeadAlgorithm enc) {
        if (key instanceof Password) {
            return encryptWith((Password) key, new Pbes2HsAkwAlgorithm(enc.getKeyBitLength()), enc);
        }
        return encryptWith(key, Jwts.KEY.DIRECT, enc);
    }

    @Override
    public <K extends Key> JwtBuilder encryptWith(final K key, final KeyAlgorithm<? super K, ?> keyAlg, final AeadAlgorithm enc) {
        this.enc = Assert.notNull(enc, "Encryption algorithm cannot be null.");
        final String encId = Assert.hasText(enc.getId(), "Encryption algorithm id cannot be null or empty.");
        this.encFunction = wrap(new Function<AeadRequest, AeadResult>() {
            @Override
            public AeadResult apply(AeadRequest request) {
                return enc.encrypt(request);
            }
        }, "%s encryption failed.", encId);

        this.key = Assert.notNull(key, "Key cannot be null.");

        //noinspection unchecked
        this.keyAlg = (KeyAlgorithm<Key, ?>) Assert.notNull(keyAlg, "KeyAlgorithm cannot be null.");
        final String algId = Assert.hasText(keyAlg.getId(), "KeyAlgorithm id cannot be null or empty.");
        final KeyAlgorithm<Key, ?> alg = this.keyAlg;
        final String cekMsg = "Unable to obtain content encryption key from key management algorithm '%s'.";
        this.keyAlgFunction = Functions.wrap(new Function<KeyRequest<Key>, KeyResult>() {
            @Override
            public KeyResult apply(KeyRequest<Key> request) {
                return alg.getEncryptionKey(request);
            }
        }, SecurityException.class, cekMsg, algId);

        return this;
    }

    @Override
    public JwtBuilder compressWith(CompressionCodec compressionCodec) {
        Assert.notNull(compressionCodec, "compressionCodec cannot be null");
        this.compressionCodec = compressionCodec;
        return this;
    }

    @Override
    public JwtBuilder setPayload(String payload) {
        byte[] bytes = payload != null ? payload.getBytes(StandardCharsets.UTF_8) : null;
        return setContent(bytes);
    }

    @Override
    public JwtBuilder setContent(byte[] content) {
        this.content = content;
        return this;
    }

    @Override
    public JwtBuilder setContent(byte[] content, String cty) {
        Assert.notEmpty(content, "content byte array cannot be null or empty.");
        Assert.hasText(cty, "Content Type String cannot be null or empty.");
        cty = CompactMediaTypeIdConverter.INSTANCE.applyFrom(cty);
        this.headerBuilder.setContentType(cty);
        return setContent(content);
    }

    @Override
    public JwtBuilder setClaims(Claims claims) {
        Assert.notNull(claims, "Claims argument cannot be null.");
        return setClaims((Map<String, ?>) claims);
    }

    @Override
    public JwtBuilder setClaims(Map<String, ?> claims) {
        Assert.notNull(claims, "Claims map cannot be null.");
        this.claimsBuilder.empty();
        this.claimsBuilder.set(claims);
        return this;
    }

    @Override
    public JwtBuilder addClaims(Map<String, ?> claims) {
        this.claimsBuilder.set(claims);
        return this;
    }

    @Override
    public JwtBuilder setIssuer(String iss) {
        this.claimsBuilder.setIssuer(iss);
        return this;
    }

    @Override
    public JwtBuilder setSubject(String sub) {
        this.claimsBuilder.setSubject(sub);
        return this;
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        this.claimsBuilder.setAudience(aud);
        return this;
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        this.claimsBuilder.setExpiration(exp);
        return this;
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        this.claimsBuilder.setNotBefore(nbf);
        return this;
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        this.claimsBuilder.setIssuedAt(iat);
        return this;
    }

    @Override
    public JwtBuilder setId(String jti) {
        this.claimsBuilder.setId(jti);
        return this;
    }

    @Override
    public JwtBuilder claim(String name, Object value) {
        this.claimsBuilder.set(name, value);
        return this;
    }

    @Override
    public String compact() {

        final boolean jwe = encFunction != null;

        if (jwe && signFunction != null) {
            String msg = "Both 'signWith' and 'encryptWith' cannot be specified - choose either.";
            throw new IllegalStateException(msg);
        }

        final Claims claims = this.claimsBuilder.build();

        if (Objects.isEmpty(content) && Collections.isEmpty(claims)) {
            if (jwe) { // JWE payload can never be empty:
                String msg = "Encrypted JWTs must have either 'claims' or non-empty 'content'.";
                throw new IllegalStateException(msg);
            } else { //JWS or Unprotected JWT payloads can be empty
                content = Bytes.EMPTY;
            }
        }
        if (!Objects.isEmpty(content) && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'content' and 'claims' cannot both be specified. Choose either one.");
        }

        if (this.serializer == null) { // try to find one based on the services available
            //noinspection unchecked
            serializeToJsonWith(Services.loadFirst(Serializer.class));
        }

        byte[] payload = content;
        if (!Collections.isEmpty(claims)) {
            payload = claimsSerializer.apply(claims);
        }
        if (!Objects.isEmpty(payload) && compressionCodec != null) {
            payload = compressionCodec.compress(payload);
            this.headerBuilder.setCompressionAlgorithm(compressionCodec.getId());
        }

        if (jwe) {
            return encrypt(payload);
        } else {
            return compact(payload);
        }
    }

    private io.jsonwebtoken.Header buildHeader() {
        return new DefaultJwtHeaderBuilder(this.headerBuilder).build();
    }

    private String compact(byte[] payload) {

        Assert.stateNotNull(sigAlg, "SignatureAlgorithm is required."); // invariant

//        if (this.key != null && !(header instanceof JwsHeader)) {
//            header = new DefaultJwsHeader(header);
//        }

        this.headerBuilder.setAlgorithm(sigAlg.getId());

        final io.jsonwebtoken.Header header = buildHeader();

        byte[] headerBytes = headerSerializer.apply(header);
        String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        String base64UrlEncodedBody = base64UrlEncoder.encode(payload);

        String jwt = base64UrlEncodedHeader + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;

        if (this.key != null) { //jwt must be signed:
            Assert.stateNotNull(key, "Signing key cannot be null.");
            Assert.stateNotNull(signFunction, "signFunction cannot be null.");
            byte[] data = jwt.getBytes(StandardCharsets.US_ASCII);
            SecureRequest<byte[], Key> request = new DefaultSecureRequest<>(data, provider, secureRandom, key);
            byte[] signature = signFunction.apply(request);
            String base64UrlSignature = base64UrlEncoder.encode(signature);
            jwt += DefaultJwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (unprotected JWT), but must terminate w/ a period, see
            // https://www.rfc-editor.org/rfc/rfc7519#section-6.1
            jwt += DefaultJwtParser.SEPARATOR_CHAR;
        }

        return jwt;
    }

    private String encrypt(byte[] payload) {

        Assert.stateNotNull(key, "Key is required."); // set by encryptWith*
        Assert.stateNotNull(enc, "Encryption algorithm is required."); // set by encryptWith*
        Assert.stateNotNull(encFunction, "Encryption function cannot be null.");
        Assert.stateNotNull(keyAlg, "KeyAlgorithm is required."); //set by encryptWith*
        Assert.stateNotNull(keyAlgFunction, "KeyAlgorithm function cannot be null.");
        Assert.notEmpty(payload, "JWE payload bytes cannot be empty."); // JWE invariant (JWS can be empty however)

        //only expose (mutable) JweHeader functionality to KeyAlgorithm instances, not the full headerBuilder
        // (which exposes this JwtBuilder and shouldn't be referenced by KeyAlgorithms):
        JweHeader delegate = new DefaultMutableJweHeader(this.headerBuilder);
        KeyRequest<Key> keyRequest = new DefaultKeyRequest<>(this.key, this.provider, this.secureRandom, delegate, enc);
        KeyResult keyResult = keyAlgFunction.apply(keyRequest);
        Assert.stateNotNull(keyResult, "KeyAlgorithm must return a KeyResult.");

        SecretKey cek = Assert.notNull(keyResult.getKey(), "KeyResult must return a content encryption key.");
        byte[] encryptedCek = Assert.notNull(keyResult.getPayload(), "KeyResult must return an encrypted key byte array, even if empty.");

        this.headerBuilder.setAlgorithm(keyAlg.getId());
        this.headerBuilder.put(DefaultJweHeader.ENCRYPTION_ALGORITHM.getId(), enc.getId());

        final io.jsonwebtoken.Header header = buildHeader();

        byte[] headerBytes = this.headerSerializer.apply(header);
        final String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        byte[] aad = base64UrlEncodedHeader.getBytes(StandardCharsets.US_ASCII);

        AeadRequest encRequest = new DefaultAeadRequest(payload, provider, secureRandom, cek, aad);
        AeadResult encResult = encFunction.apply(encRequest);

        byte[] iv = Assert.notEmpty(encResult.getInitializationVector(), "Encryption result must have a non-empty initialization vector.");
        byte[] ciphertext = Assert.notEmpty(encResult.getPayload(), "Encryption result must have non-empty ciphertext (result.getData()).");
        byte[] tag = Assert.notEmpty(encResult.getDigest(), "Encryption result must have a non-empty authentication tag.");

        String base64UrlEncodedEncryptedCek = base64UrlEncoder.encode(encryptedCek);
        String base64UrlEncodedIv = base64UrlEncoder.encode(iv);
        String base64UrlEncodedCiphertext = base64UrlEncoder.encode(ciphertext);
        String base64UrlEncodedTag = base64UrlEncoder.encode(tag);

        return base64UrlEncodedHeader + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedEncryptedCek + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedIv + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedCiphertext + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedTag;
    }

    private static class DefaultJwtBuilderHeader extends DefaultJweHeaderBuilder<Header>
            implements JwtBuilder.Header {

        private final JwtBuilder builder;

        public DefaultJwtBuilderHeader(JwtBuilder builder) {
            super();
            this.builder = Assert.notNull(builder, "JwtBuilder cannot be null.");
        }

        @Override
        public JwtBuilder and() {
            return builder;
        }
    }
}

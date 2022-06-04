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
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.DefaultAeadRequest;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.DefaultSignatureRequest;
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm;
import io.jsonwebtoken.impl.security.SignatureAlgorithmsBridge;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithms;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.PasswordKey;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithms;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

public class DefaultJwtBuilder implements JwtBuilder {

    protected Provider provider;
    protected SecureRandom secureRandom;

    protected Header<?> header;
    protected Claims claims;
    protected byte[] payload;

    private SignatureAlgorithm<Key, ?> sigAlg = SignatureAlgorithms.NONE;
    private Function<SignatureRequest<Key>, byte[]> signFunction;

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
    public JwtBuilder setHeader(Header<?> header) {
        this.header = header;
        return this;
    }

    @Override
    public JwtBuilder setHeader(Map<String, ?> header) {
        this.header = new DefaultUnprotectedHeader(header);
        return this;
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, ?> params) {
        if (!Collections.isEmpty(params)) {
            Header<?> header = ensureHeader();
            header.putAll(params);
        }
        return this;
    }

    protected Header<?> ensureHeader() {
        if (this.header == null) {
            this.header = new DefaultUnprotectedHeader();
        }
        return this.header;
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        ensureHeader().put(name, value);
        return this;
    }

    @Override
    public JwtBuilder signWith(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        SignatureAlgorithm<Key, ?> alg = SignatureAlgorithmsBridge.forSigningKey(key);
        return signWith(key, alg);
    }

    @Override
    public <K extends Key> JwtBuilder signWith(K key, final SignatureAlgorithm<K, ?> alg) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        this.key = key;
        //noinspection unchecked
        this.sigAlg = (SignatureAlgorithm<Key, ?>) alg;
        String id = Assert.hasText(this.sigAlg.getId(), "SignatureAlgorithm id cannot be null or empty.");
        if (SignatureAlgorithms.NONE.getId().equalsIgnoreCase(id)) {
            String msg = "The 'none' SignatureAlgorithm cannot be used to sign JWTs.";
            throw new IllegalArgumentException(msg);
        }
        this.signFunction = Functions.wrap(new Function<SignatureRequest<Key>, byte[]>() {
            @Override
            public byte[] apply(SignatureRequest<Key> request) {
                return sigAlg.sign(request);
            }
        }, SignatureException.class, "Unable to compute %s signature.", id);
        return this;
    }

    @SuppressWarnings({"deprecation", "unchecked"}) // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(Key key, io.jsonwebtoken.SignatureAlgorithm alg) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        alg.assertValidSigningKey(key); //since 0.10.0 for https://github.com/jwtk/jjwt/issues/334
        return signWith(key, (SignatureAlgorithm<Key, ?>) SignatureAlgorithmsBridge.forId(alg.getValue()));
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
    public JwtBuilder encryptWith(AeadAlgorithm enc, SecretKey key) {
        if (key instanceof PasswordKey) {
            return encryptWith(enc, (PasswordKey) key, new Pbes2HsAkwAlgorithm(enc.getKeyBitLength()));
        }
        return encryptWith(enc, key, KeyAlgorithms.DIRECT);
    }

    @Override
    public <K extends Key> JwtBuilder encryptWith(final AeadAlgorithm enc, final K key, final KeyAlgorithm<K, ?> keyAlg) {
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
        String cekMsg = "Unable to obtain content encryption key from key management algorithm '%s'.";
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
        return setPayload(bytes);
    }

    @Override
    public JwtBuilder setPayload(byte[] payload) {
        this.payload = payload;
        return this;
    }

    protected Claims ensureClaims() {
        if (this.claims == null) {
            this.claims = new DefaultClaims();
        }
        return this.claims;
    }

    @Override
    public JwtBuilder setClaims(Claims claims) {
        this.claims = claims;
        return this;
    }

    @Override
    public JwtBuilder setClaims(Map<String, ?> claims) {
        this.claims = new DefaultClaims(claims);
        return this;
    }

    @Override
    public JwtBuilder addClaims(Map<String, ?> claims) {
        ensureClaims().putAll(claims);
        return this;
    }

    @Override
    public JwtBuilder setIssuer(String iss) {
        return claim(DefaultClaims.ISSUER.getId(), iss);
    }

    @Override
    public JwtBuilder setSubject(String sub) {
        return claim(DefaultClaims.SUBJECT.getId(), sub);
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        return claim(DefaultClaims.AUDIENCE.getId(), aud);
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        return claim(DefaultClaims.EXPIRATION.getId(), exp);
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        return claim(DefaultClaims.NOT_BEFORE.getId(), nbf);
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        return claim(DefaultClaims.ISSUED_AT.getId(), iat);
    }

    @Override
    public JwtBuilder setId(String jti) {
        return claim(DefaultClaims.JTI.getId(), jti);
    }

    @Override
    public JwtBuilder claim(String name, Object value) {
        Assert.hasText(name, "Claim property name cannot be null or empty.");
        if (value instanceof String && !Strings.hasText((String) value)) {
            value = null;
        }
        if (this.claims == null) {
            if (value != null) {
                ensureClaims().put(name, value);
            }
        } else {
            if (value == null) {
                this.claims.remove(name);
            } else {
                this.claims.put(name, value);
            }
        }
        return this;
    }

    @Override
    public String compact() {

        final boolean jwe = encFunction != null;

        if (jwe && signFunction != null) {
            String msg = "Both 'signWith' and 'encryptWith' cannot be specified - choose either.";
            throw new IllegalStateException(msg);
        }

        if (Objects.isEmpty(payload) && Collections.isEmpty(claims)) {
            if (jwe) { // JWE payload can never be empty:
                String msg = "Encrypted JWTs must have either 'claims' or a non-empty 'payload'.";
                throw new IllegalStateException(msg);
            } else { //JWS or Unprotected JWT payloads can be empty
                payload = Bytes.EMPTY;
            }
        }
        if (!Objects.isEmpty(payload) && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'payload' and 'claims' cannot both be specified. Choose either one.");
        }

        Header<?> header = ensureHeader();

        if (this.serializer == null) { // try to find one based on the services available
            //noinspection unchecked
            serializeToJsonWith(Services.loadFirst(Serializer.class));
        }

        byte[] body = payload;
        if (!Collections.isEmpty(claims)) {
            body = claimsSerializer.apply(claims);
        }
        if (!Objects.isEmpty(body) && compressionCodec != null) {
            body = compressionCodec.compress(body);
            header.setCompressionAlgorithm(compressionCodec.getId());
        }

        if (jwe) {
            JweHeader jweHeader = header instanceof JweHeader ? (JweHeader) header : new DefaultJweHeader(header);
            return encrypt(jweHeader, body);
        } else {
            return compact(header, body);
        }
    }

    private String compact(Header<?> header, byte[] body) {

        Assert.stateNotNull(sigAlg, "SignatureAlgorithm is required."); // invariant

        if (this.key != null && !(header instanceof JwsHeader)) {
            header = new DefaultJwsHeader(header);
        }

        header.setAlgorithm(sigAlg.getId());

        byte[] headerBytes = headerSerializer.apply(header);
        String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        String base64UrlEncodedBody = base64UrlEncoder.encode(body);

        String jwt = base64UrlEncodedHeader + DefaultJwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;

        if (this.key != null) { //jwt must be signed:
            Assert.stateNotNull(key, "Signing key cannot be null.");
            Assert.stateNotNull(signFunction, "signFunction cannot be null.");
            byte[] data = jwt.getBytes(StandardCharsets.US_ASCII);
            SignatureRequest<Key> request = new DefaultSignatureRequest<>(provider, secureRandom, data, key);
            byte[] signature = signFunction.apply(request);
            String base64UrlSignature = base64UrlEncoder.encode(signature);
            jwt += DefaultJwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (unprotected JWT), but must terminate w/ a period, see
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1
            jwt += DefaultJwtParser.SEPARATOR_CHAR;
        }

        return jwt;
    }

    private String encrypt(JweHeader header, byte[] body) {

        Assert.stateNotNull(key, "Key is required."); // set by encryptWith*
        Assert.stateNotNull(enc, "Encryption algorithm is required."); // set by encryptWith*
        Assert.stateNotNull(encFunction, "Encryption function cannot be null.");
        Assert.stateNotNull(keyAlg, "KeyAlgorithm is required."); //set by encryptWith*
        Assert.stateNotNull(keyAlgFunction, "KeyAlgorithm function cannot be null.");
        Assert.notEmpty(body, "JWE content bytes cannot be empty."); // JWE invariant (JWS can be empty however)

        KeyRequest<Key> keyRequest = new DefaultKeyRequest<>(this.provider, this.secureRandom, this.key, header, enc);
        KeyResult keyResult = keyAlgFunction.apply(keyRequest);

        Assert.stateNotNull(keyRequest, "KeyAlgorithm must return a KeyResult.");
        SecretKey cek = Assert.notNull(keyResult.getKey(), "KeyResult must return a content encryption key.");
        byte[] encryptedCek = Assert.notNull(keyResult.getContent(), "KeyResult must return an encrypted key byte array, even if empty.");

        header.put(AbstractHeader.ALGORITHM.getId(), keyAlg.getId());
        header.put(DefaultJweHeader.ENCRYPTION_ALGORITHM.getId(), enc.getId());

        byte[] headerBytes = this.headerSerializer.apply(header);
        final String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        byte[] aad = base64UrlEncodedHeader.getBytes(StandardCharsets.US_ASCII);

        AeadRequest encRequest = new DefaultAeadRequest(provider, secureRandom, body, cek, aad);
        AeadResult encResult = encFunction.apply(encRequest);

        byte[] iv = Assert.notEmpty(encResult.getInitializationVector(), "Encryption result must have a non-empty initialization vector.");
        byte[] ciphertext = Assert.notEmpty(encResult.getContent(), "Encryption result must have non-empty ciphertext (result.getData()).");
        byte[] tag = Assert.notEmpty(encResult.getDigest(), "Encryption result must have a non-empty authentication tag.");

        String base64UrlEncodedEncryptedCek = base64UrlEncoder.encode(encryptedCek);
        String base64UrlEncodedIv = base64UrlEncoder.encode(iv);
        String base64UrlEncodedCiphertext = base64UrlEncoder.encode(ciphertext);
        String base64UrlEncodedTag = base64UrlEncoder.encode(tag);

        return base64UrlEncodedHeader + DefaultJwtParser.SEPARATOR_CHAR +
                base64UrlEncodedEncryptedCek + DefaultJwtParser.SEPARATOR_CHAR +
                base64UrlEncodedIv + DefaultJwtParser.SEPARATOR_CHAR +
                base64UrlEncodedCiphertext + DefaultJwtParser.SEPARATOR_CHAR +
                base64UrlEncodedTag;
    }
}

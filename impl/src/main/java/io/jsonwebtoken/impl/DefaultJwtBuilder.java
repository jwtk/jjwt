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
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.io.SerializingMapWriter;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.io.WritingSerializer;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.DefaultAeadRequest;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.DefaultSecureRequest;
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm;
import io.jsonwebtoken.impl.security.ProviderKey;
import io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithms;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.io.Writer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
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
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class DefaultJwtBuilder implements JwtBuilder {

    private static final String PUB_KEY_SIGN_MSG = "PublicKeys may not be used to create digital signatures. " +
            "PrivateKeys are used to sign, and PublicKeys are used to verify.";

    private static final String PRIV_KEY_ENC_MSG = "PrivateKeys may not be used to encrypt data. PublicKeys are " +
            "used to encrypt, and PrivateKeys are used to decrypt.";

    protected Provider provider;
    protected SecureRandom secureRandom;

    private final DefaultBuilderHeader headerBuilder;
    private final DefaultBuilderClaims claimsBuilder;

    private Payload payload = Payload.EMPTY;

    private SecureDigestAlgorithm<Key, ?> sigAlg = Jwts.SIG.NONE;
    private Function<SecureRequest<byte[], Key>, byte[]> signFunction;

    private AeadAlgorithm enc; // MUST be Symmetric AEAD per https://tools.ietf.org/html/rfc7516#section-4.1.2
    private Function<AeadRequest, AeadResult> encFunction;

    private KeyAlgorithm<Key, ?> keyAlg;
    private Function<KeyRequest<Key>, KeyResult> keyAlgFunction;

    private Key key;

    private Writer<Map<String, ?>> jsonWriter;

    protected Encoder<byte[], String> encoder = Encoders.BASE64URL;
    private boolean encodePayload = true;
    protected CompressionAlgorithm compressionAlgorithm;

    public DefaultJwtBuilder() {
        this.headerBuilder = new DefaultBuilderHeader(this);
        this.claimsBuilder = new DefaultBuilderClaims(this);
    }

    @Override
    public BuilderHeader header() {
        return this.headerBuilder;
    }

    @Override
    public BuilderClaims claims() {
        return this.claimsBuilder;
    }

    @Override
    public JwtBuilder provider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public JwtBuilder random(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    protected <I, O> Function<I, O> wrap(Function<I, O> fn, String fmt, Object... args) {
        return Functions.wrap(fn, SecurityException.class, fmt, args);
    }

    @SuppressWarnings("deprecation")
    @Override
    public JwtBuilder serializeToJsonWith(final Serializer<Map<String, ?>> serializer) {
        return jsonWriter(new SerializingMapWriter(serializer));
    }

    @Override
    public JwtBuilder jsonWriter(Writer<Map<String, ?>> writer) {
        this.jsonWriter = Assert.notNull(writer, "JSON Writer cannot be null.");
        return this;
    }

//    private byte[] serialize(Map<String, ?> map) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream(4096);
//        try {
//            serialize(baos, map);
//        } finally {
//            Objects.nullSafeClose(baos);
//        }
//        return baos.toByteArray();
//    }

    @Override
    public JwtBuilder base64UrlEncodeWith(Encoder<byte[], String> encoder) {
        return encoder(encoder);
    }

    @Override
    public JwtBuilder encoder(Encoder<byte[], String> encoder) {
        Assert.notNull(encoder, "encoder cannot be null.");
        this.encoder = encoder;
        return this;
    }

    @Override
    public JwtBuilder encodePayload(boolean b64) {
        this.encodePayload = b64;
        // clear out any previous values. They will be applied appropriately during compact()
        String critParamId = DefaultProtectedHeader.CRIT.getId();
        String b64Id = DefaultJwsHeader.B64.getId();
        Set<String> crit = this.headerBuilder.get(DefaultProtectedHeader.CRIT);
        crit = new LinkedHashSet<>(Collections.nullSafe(crit));
        crit.remove(b64Id);
        return header().delete(b64Id).add(critParamId, crit).and();
    }

    @Override
    public JwtBuilder setHeader(Map<String, ?> map) {
        return this.headerBuilder.empty().add(map).and();
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, ?> params) {
        return this.headerBuilder.add(params).and();
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        return this.headerBuilder.add(name, value).and();
    }

    protected static <K extends Key> SecureDigestAlgorithm<K, ?> forSigningKey(K key) {
        Assert.notNull(key, "Key cannot be null.");
        SecureDigestAlgorithm<K, ?> alg = StandardSecureDigestAlgorithms.findBySigningKey(key);
        if (alg == null) {
            String msg = "Unable to determine a suitable MAC or Signature algorithm for the specified key using " +
                    "available heuristics: either the key size is too weak be used with available algorithms, or the " +
                    "key size is unavailable (e.g. if using a PKCS11 or HSM (Hardware Security Module) key store). " +
                    "If you are using a PKCS11 or HSM keystore, consider using the " +
                    "JwtBuilder.signWith(Key, SecureDigestAlgorithm) method instead.";
            throw new UnsupportedKeyException(msg);
        }
        return alg;
    }

    @Override
    public JwtBuilder signWith(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        SecureDigestAlgorithm<Key, ?> alg = forSigningKey(key); // https://github.com/jwtk/jjwt/issues/381
        return signWith(key, alg);
    }

    @Override
    public <K extends Key> JwtBuilder signWith(K key, final SecureDigestAlgorithm<? super K, ?> alg)
            throws InvalidKeyException {

        Assert.notNull(key, "Key argument cannot be null.");
        if (key instanceof PublicKey) { // it's always wrong/insecure to try to create signatures with PublicKeys:
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
        Assert.isTrue(alg.isHmac(), "Key bytes may only be specified for HMAC signatures.  " +
                "If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        SecretKey key = new SecretKeySpec(secretKeyBytes, alg.getJcaName());
        return signWith(key, alg);
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public JwtBuilder signWith(io.jsonwebtoken.SignatureAlgorithm alg, String base64EncodedSecretKey) throws InvalidKeyException {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Base64-encoded key bytes may only be specified for HMAC signatures.  " +
                "If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
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

        Assert.notNull(key, "Encryption key cannot be null.");
        if (key instanceof PrivateKey) {
            throw new IllegalArgumentException(PRIV_KEY_ENC_MSG);
        }
        Assert.notNull(keyAlg, "KeyAlgorithm cannot be null.");
        final String algId = Assert.hasText(keyAlg.getId(), "KeyAlgorithm id cannot be null or empty.");

        this.key = key;
        //noinspection unchecked
        this.keyAlg = (KeyAlgorithm<Key, ?>) keyAlg;
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
    public JwtBuilder compressWith(CompressionAlgorithm alg) {
        Assert.notNull(alg, "CompressionAlgorithm cannot be null");
        Assert.hasText(alg.getId(), "CompressionAlgorithm id cannot be null or empty.");
        this.compressionAlgorithm = alg;
        // clear out any previous value that might have been there.  It'll be added back to match this
        // specific algorithm in the compact() method implementation
        return header().delete(DefaultHeader.COMPRESSION_ALGORITHM.getId()).and();
    }

    @Override
    public JwtBuilder setPayload(String payload) {
        return content(payload);
    }

    @Override
    public JwtBuilder content(String content) {
        if (Strings.hasText(content)) {
            this.payload = new Payload(content, null);
        }
        return this;
    }

    @Override
    public JwtBuilder content(byte[] content) {
        if (!Bytes.isEmpty(content)) {
            this.payload = new Payload(content, null);
        }
        return this;
    }

    @Override
    public JwtBuilder content(byte[] content, String cty) {
        Assert.notEmpty(content, "content byte array cannot be null or empty.");
        Assert.hasText(cty, "Content Type String cannot be null or empty.");
        this.payload = new Payload(content, cty);
        // clear out any previous value - it will be set appropriately during compact()
        return header().delete(DefaultHeader.CONTENT_TYPE.getId()).and();
    }

    @Override
    public JwtBuilder setClaims(Map<String, ?> claims) {
        Assert.notNull(claims, "Claims map cannot be null.");
        return claims().empty().add(claims).and();
    }

    @Override
    public JwtBuilder addClaims(Map<String, ?> claims) {
        return claims(claims);
    }

    @Override
    public JwtBuilder claims(Map<String, ?> claims) {
        return claims().add(claims).and();
    }

    @Override
    public JwtBuilder claim(String name, Object value) {
        return claims().add(name, value).and();
    }

    @Override
    public JwtBuilder setIssuer(String iss) {
        return issuer(iss);
    }

    @Override
    public JwtBuilder issuer(String iss) {
        return claims().issuer(iss).and();
    }

    @Override
    public JwtBuilder setSubject(String sub) {
        return subject(sub);
    }

    @Override
    public JwtBuilder subject(String sub) {
        this.claimsBuilder.subject(sub);
        return this;
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        this.claimsBuilder.setAudience(aud);
        return this;
    }

    @Override
    public JwtBuilder audienceSingle(String aud) {
        this.claimsBuilder.audienceSingle(aud);
        return this;
    }

    @Override
    public JwtBuilder audience(String aud) {
        this.claimsBuilder.audience(aud);
        return this;
    }

    @Override
    public JwtBuilder audience(Collection<String> aud) {
        this.claimsBuilder.audience(aud);
        return this;
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        return expiration(exp);
    }

    @Override
    public JwtBuilder expiration(Date exp) {
        this.claimsBuilder.expiration(exp);
        return this;
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        return notBefore(nbf);
    }

    @Override
    public JwtBuilder notBefore(Date nbf) {
        this.claimsBuilder.notBefore(nbf);
        return this;
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        return issuedAt(iat);
    }

    @Override
    public JwtBuilder issuedAt(Date iat) {
        this.claimsBuilder.issuedAt(iat);
        return this;
    }

    @Override
    public JwtBuilder setId(String jti) {
        return id(jti);
    }

    @Override
    public JwtBuilder id(String jti) {
        this.claimsBuilder.id(jti);
        return this;
    }

    private void assertPayloadEncoding(String type) {
        if (!this.encodePayload) {
            String msg = "Payload encoding may not be disabled for " + type + "s, only JWSs.";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    public String compact() {

        final boolean jwe = encFunction != null;

        if (jwe && signFunction != null) {
            String msg = "Both 'signWith' and 'encryptWith' cannot be specified. Choose either one.";
            throw new IllegalStateException(msg);
        }

        Payload content = Assert.stateNotNull(this.payload, "content instance null, internal error");
        final Claims claims = this.claimsBuilder.build();

        if (jwe && content.isEmpty() && Collections.isEmpty(claims)) { // JWE payload can never be empty:
            String msg = "Encrypted JWTs must have either 'claims' or non-empty 'content'.";
            throw new IllegalStateException(msg);
        } // otherwise JWS and Unprotected JWT payloads can be empty

        if (!content.isEmpty() && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'content' and 'claims' cannot be specified. Choose either one.");
        }

        if (this.jsonWriter == null) { // try to find one based on the services available
            //noinspection unchecked
            jsonWriter(Services.loadFirst(Writer.class));
        }

        if (!Collections.isEmpty(claims)) { // normalize so we have one object to deal with:
            content = new Payload(claims, content.getContentType());
        }
        if (compressionAlgorithm != null && !content.isEmpty()) {
            content.setZip(compressionAlgorithm);
            this.headerBuilder.put(DefaultHeader.COMPRESSION_ALGORITHM.getId(), compressionAlgorithm.getId());
        }

        if (Strings.hasText(content.getContentType())) {
            // We retain the value from the content* calls to prevent accidental removal from
            // header().empty() or header().delete calls
            this.headerBuilder.contentType(content.getContentType());
        }

        Provider keyProvider = ProviderKey.getProvider(this.key, this.provider);
        Key key = ProviderKey.getKey(this.key);
        if (jwe) {
            return encrypt(content, key, keyProvider);
        } else if (key != null) {
            return sign(content, key, keyProvider);
        } else {
            return unprotected(content);
        }
    }

    // automatically closes the OutputStream
    private void writeAndClose(OutputStream os, Map<String, ?> map) {
        Nameable nameable = Assert.isInstanceOf(Nameable.class, map, "JWT internal maps implement Nameable.");
        Writer<Map<String, ?>> jsonWriter = Assert.stateNotNull(this.jsonWriter, "JSON Writer cannot be null.");
        WritingSerializer<Map<String, ?>> serializer = new WritingSerializer<>(jsonWriter, nameable.getName());
        java.io.Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8);
        try {
            serializer.accept(writer, map);
        } finally {
            Objects.nullSafeClose(writer);
        }
    }

    private long writeAndClose(OutputStream out, final Payload payload) {
        out = payload.wrap(out); // compression if necessary
        if (payload.hasClaims()) {
            writeAndClose(out, payload.getRequiredClaims());
            return -1;
        } else {
            try {
                return Streams.copy(payload.toInputStream(), out, new byte[4096], "Unable to write payload.");
            } finally {
                Objects.nullSafeClose(out);
            }
        }
    }

    private String sign(final Payload content, final Key key, final Provider provider) {

        Assert.stateNotNull(key, "Key is required."); // set by signWithWith*
        Assert.stateNotNull(sigAlg, "SignatureAlgorithm is required."); // invariant
        Assert.stateNotNull(signFunction, "Signature Algorithm function cannot be null.");
        Assert.stateNotNull(content, "Payload argument cannot be null.");

        // ----- header -----
        this.headerBuilder.add(DefaultHeader.ALGORITHM.getId(), sigAlg.getId());
        if (!this.encodePayload) { // b64 extension:
            String id = DefaultJwsHeader.B64.getId();
            this.headerBuilder.critical(id).add(id, false);
        }
        final JwsHeader header = Assert.isInstanceOf(JwsHeader.class, this.headerBuilder.build());
        final ByteArrayOutputStream jws = new ByteArrayOutputStream(4096);
        OutputStream out = this.encoder.wrap(jws);
        writeAndClose(out, header);

        // ----- separator -----
        jws.write(DefaultJwtParser.SEPARATOR_CHAR);

        // ----- payload -----
        // Logic defined by table in https://datatracker.ietf.org/doc/html/rfc7797#section-3 :
        byte[] signingInput;
        if (this.encodePayload) {
            out = this.encoder.wrap(jws);
            writeAndClose(out, content);
            signingInput = jws.toByteArray();
        } else { // b64

            // First, include the base64url header bytes + the SEPARATOR_CHAR byte:
            ByteArrayOutputStream pos = new ByteArrayOutputStream(4096);
            Streams.write(pos, jws.toByteArray(), "Unable to copy header bytes for signature verification.");

            // Next, b64 extension requires the raw (non-encoded) payload to be included directly in the signing input:
            long copied = writeAndClose(pos, content);
            if (copied <= 0) {
                String msg = "'b64' Unencoded payload option has been specified, but payload is empty.";
                throw new IllegalStateException(msg);
            }

            signingInput = pos.toByteArray(); // base64url header bytes + separator char + raw payload bytes

            if (Strings.hasText(content.getString())) {
                // 'unencoded non-detached' per https://datatracker.ietf.org/doc/html/rfc7797#section-5.2
                byte[] utf8 = Strings.utf8(content.getString());
                Streams.write(jws, utf8, "Unable to write non-detached String bytes.");
            }
        }

        // ----- separator -----
        jws.write(DefaultJwtParser.SEPARATOR_CHAR);

        // ----- signature -----
        SecureRequest<byte[], Key> request = new DefaultSecureRequest<>(signingInput, provider, secureRandom, key);
        byte[] signature = signFunction.apply(request);
        out = this.encoder.wrap(jws);
        Streams.writeAndClose(out, signature, "Unable to write signature bytes");

        return Strings.utf8(jws.toByteArray());
    }

    private String unprotected(final Payload content) {

        Assert.stateNotNull(content, "Content argument cannot be null.");
        assertPayloadEncoding("unprotected JWT");

        this.headerBuilder.add(DefaultHeader.ALGORITHM.getId(), Jwts.SIG.NONE.getId());

        // ----- header -----
        final Header header = this.headerBuilder.build();
        final ByteArrayOutputStream jwt = new ByteArrayOutputStream(512);
        OutputStream out = this.encoder.wrap(jwt);
        writeAndClose(out, header);

        // ----- payload -----
        jwt.write(DefaultJwtParser.SEPARATOR_CHAR);
        out = this.encoder.wrap(jwt);
        writeAndClose(out, content);

        // ----- period terminator -----
        jwt.write(DefaultJwtParser.SEPARATOR_CHAR); // https://www.rfc-editor.org/rfc/rfc7519#section-6.1

        return Strings.ascii(jwt.toByteArray());
    }

    private String encrypt(final Payload content, final Key key, final Provider keyProvider) {

        Assert.stateNotNull(content, "Payload argument cannot be null.");
        Assert.stateNotNull(key, "Key is required."); // set by encryptWith*
        Assert.stateNotNull(enc, "Encryption algorithm is required."); // set by encryptWith*
        Assert.stateNotNull(encFunction, "Encryption function cannot be null.");
        Assert.stateNotNull(keyAlg, "KeyAlgorithm is required."); //set by encryptWith*
        Assert.stateNotNull(keyAlgFunction, "KeyAlgorithm function cannot be null.");
        assertPayloadEncoding("JWE");

        ByteArrayOutputStream pos = new ByteArrayOutputStream(4096);
        writeAndClose(pos, content);
        final byte[] payload = Assert.notEmpty(pos.toByteArray(),
                "JWE payload bytes cannot be empty."); // JWE invariant (JWS can be empty however)

        //only expose (mutable) JweHeader functionality to KeyAlgorithm instances, not the full headerBuilder
        // (which exposes this JwtBuilder and shouldn't be referenced by KeyAlgorithms):
        JweHeader delegate = new DefaultMutableJweHeader(this.headerBuilder);
        KeyRequest<Key> keyRequest = new DefaultKeyRequest<>(key, keyProvider, this.secureRandom, delegate, enc);
        KeyResult keyResult = keyAlgFunction.apply(keyRequest);
        Assert.stateNotNull(keyResult, "KeyAlgorithm must return a KeyResult.");

        SecretKey cek = Assert.notNull(keyResult.getKey(), "KeyResult must return a content encryption key.");
        byte[] encryptedCek = Assert.notNull(keyResult.getPayload(),
                "KeyResult must return an encrypted key byte array, even if empty.");

        this.headerBuilder.add(DefaultHeader.ALGORITHM.getId(), keyAlg.getId());
        this.headerBuilder.put(DefaultJweHeader.ENCRYPTION_ALGORITHM.getId(), enc.getId());

        final JweHeader header = Assert.isInstanceOf(JweHeader.class, this.headerBuilder.build(),
                "Invalid header created: ");

        ByteArrayOutputStream jwe = new ByteArrayOutputStream(4096);
        OutputStream out = this.encoder.wrap(jwe); // automatically base64url-encode as we write
        writeAndClose(out, header);
        Objects.nullSafeClose(out); // closes/flushes the 'out' (base64url-encoding) stream, not 'jwe' (since BAOSs don't close)

        // JWE RFC requires AAD to be the ASCII bytes of the Base64URL-encoded header. Since the header bytes are
        // already Base64URL-encoded at this point (via the encoder.wrap call just above), and Base64Url-encoding uses
        // only ASCII characters, we don't need to use StandardCharsets.US_ASCII to explicitly convert here - just
        // use the already-encoded (ascii) bytes:
        byte[] aad = jwe.toByteArray();

        // During encryption, the configured Provider applies to the KeyAlgorithm, not the AeadAlgorithm, mostly
        // because all JVMs support the standard AeadAlgorithms (especially with BouncyCastle in the classpath).
        // As such, the provider here is intentionally omitted (null):
        // TODO: add encProvider(Provider) builder method that applies to this request only?
        AeadRequest encRequest = new DefaultAeadRequest(payload, null, secureRandom, cek, aad);
        AeadResult encResult = encFunction.apply(encRequest);

        byte[] iv = Assert.notEmpty(encResult.getInitializationVector(),
                "Encryption result must have a non-empty initialization vector.");
        byte[] ciphertext = Assert.notEmpty(encResult.getPayload(),
                "Encryption result must have non-empty ciphertext (result.getData()).");
        byte[] tag = Assert.notEmpty(encResult.getDigest(),
                "Encryption result must have a non-empty authentication tag.");

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        Streams.writeAndClose(this.encoder.wrap(jwe), encryptedCek, "Unable to write encrypted CEK.");

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        Streams.writeAndClose(this.encoder.wrap(jwe), iv, "Unable to write initialization vector.");

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        Streams.writeAndClose(this.encoder.wrap(jwe), ciphertext, "Unable to write ciphertext.");

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        Streams.writeAndClose(this.encoder.wrap(jwe), tag, "Unable to write AAD tag.");

        return Strings.utf8(jwe.toByteArray());
    }

    private static class DefaultBuilderClaims extends DelegatingClaimsMutator<BuilderClaims> implements BuilderClaims {

        private final JwtBuilder builder;

        private DefaultBuilderClaims(JwtBuilder builder) {
            super();
            this.builder = builder;
        }

        @Override
        public JwtBuilder and() {
            return this.builder;
        }

        private io.jsonwebtoken.Claims build() {
            return new DefaultClaims(this.DELEGATE);
        }
    }

    private static class DefaultBuilderHeader extends DefaultJweHeaderBuilder<BuilderHeader> implements BuilderHeader {

        private final JwtBuilder builder;

        private DefaultBuilderHeader(JwtBuilder builder) {
            super();
            this.builder = Assert.notNull(builder, "JwtBuilder cannot be null.");
        }

        @Override
        public JwtBuilder and() {
            return builder;
        }

        @SuppressWarnings("SameParameterValue")
        private <T> T get(Parameter<T> param) {
            return this.DELEGATE.get(param);
        }

        private Header build() {
            return new DefaultJwtHeaderBuilder(this).build();
        }
    }

}

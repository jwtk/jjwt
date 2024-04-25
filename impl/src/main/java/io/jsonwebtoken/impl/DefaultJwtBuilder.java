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
import io.jsonwebtoken.impl.io.Base64UrlStreamEncoder;
import io.jsonwebtoken.impl.io.ByteBase64UrlStreamEncoder;
import io.jsonwebtoken.impl.io.CountingInputStream;
import io.jsonwebtoken.impl.io.EncodingOutputStream;
import io.jsonwebtoken.impl.io.NamedSerializer;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.io.UncloseableInputStream;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.DefaultAeadRequest;
import io.jsonwebtoken.impl.security.DefaultAeadResult;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.DefaultSecureRequest;
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm;
import io.jsonwebtoken.impl.security.ProviderKey;
import io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithms;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
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
    private Function<SecureRequest<InputStream, Key>, byte[]> signFunction;

    private AeadAlgorithm enc; // MUST be Symmetric AEAD per https://tools.ietf.org/html/rfc7516#section-4.1.2

    private KeyAlgorithm<Key, ?> keyAlg;
    private Function<KeyRequest<Key>, KeyResult> keyAlgFunction;

    private Key key;

    private Serializer<Map<String, ?>> serializer;

    protected Encoder<OutputStream, OutputStream> encoder = Base64UrlStreamEncoder.INSTANCE;
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

    @Override
    public JwtBuilder serializeToJsonWith(final Serializer<Map<String, ?>> serializer) {
        return json(serializer);
    }

    @Override
    public JwtBuilder json(Serializer<Map<String, ?>> serializer) {
        this.serializer = Assert.notNull(serializer, "JSON Serializer cannot be null.");
        return this;
    }

    @Override
    public JwtBuilder base64UrlEncodeWith(Encoder<byte[], String> encoder) {
        return b64Url(new ByteBase64UrlStreamEncoder(encoder));
    }

    @Override
    public JwtBuilder b64Url(Encoder<OutputStream, OutputStream> encoder) {
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
        return header().empty().add(map).and();
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, ?> params) {
        return header().add(params).and();
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        return header().add(name, value).and();
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
        this.signFunction = Functions.wrap(new Function<SecureRequest<InputStream, Key>, byte[]>() {
            @Override
            public byte[] apply(SecureRequest<InputStream, Key> request) {
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
        Assert.hasText(enc.getId(), "Encryption algorithm id cannot be null or empty.");

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
    public JwtBuilder content(InputStream in) {
        if (in != null) {
            this.payload = new Payload(in, null);
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
    public JwtBuilder content(String content, String cty) throws IllegalArgumentException {
        Assert.hasText(content, "Content string cannot be null or empty.");
        Assert.hasText(cty, "ContentType string cannot be null or empty.");
        this.payload = new Payload(content, cty);
        // clear out any previous value - it will be set appropriately during compact()
        return header().delete(DefaultHeader.CONTENT_TYPE.getId()).and();
    }

    @Override
    public JwtBuilder content(InputStream in, String cty) throws IllegalArgumentException {
        Assert.notNull(in, "Payload InputStream cannot be null.");
        Assert.hasText(cty, "ContentType string cannot be null or empty.");
        this.payload = new Payload(in, cty);
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
        return claims().subject(sub).and();
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        //noinspection deprecation
        return claims().setAudience(aud).and();
    }

    @Override
    public AudienceCollection<JwtBuilder> audience() {
        return new DelegateAudienceCollection<>((JwtBuilder) this, claims().audience());
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        return expiration(exp);
    }

    @Override
    public JwtBuilder expiration(Date exp) {
        return claims().expiration(exp).and();
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        return notBefore(nbf);
    }

    @Override
    public JwtBuilder notBefore(Date nbf) {
        return claims().notBefore(nbf).and();
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        return issuedAt(iat);
    }

    @Override
    public JwtBuilder issuedAt(Date iat) {
        return claims().issuedAt(iat).and();
    }

    @Override
    public JwtBuilder setId(String jti) {
        return id(jti);
    }

    @Override
    public JwtBuilder id(String jti) {
        return claims().id(jti).and();
    }

    private void assertPayloadEncoding(String type) {
        if (!this.encodePayload) {
            String msg = "Payload encoding may not be disabled for " + type + "s, only JWSs.";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    public String compact() {

        final boolean jwe = this.enc != null;

        if (jwe && signFunction != null) {
            String msg = "Both 'signWith' and 'encryptWith' cannot be specified. Choose either one.";
            throw new IllegalStateException(msg);
        }

        Payload payload = Assert.stateNotNull(this.payload, "Payload instance null, internal error");
        final Claims claims = this.claimsBuilder.build();

        if (jwe && payload.isEmpty() && Collections.isEmpty(claims)) { // JWE payload can never be empty:
            String msg = "Encrypted JWTs must have either 'claims' or non-empty 'content'.";
            throw new IllegalStateException(msg);
        } // otherwise JWS and Unprotected JWT payloads can be empty

        if (!payload.isEmpty() && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'content' and 'claims' cannot be specified. Choose either one.");
        }

        if (this.serializer == null) { // try to find one based on the services available
            //noinspection unchecked
            json(Services.get(Serializer.class));
        }

        if (!Collections.isEmpty(claims)) { // normalize so we have one object to deal with:
            payload = new Payload(claims);
        }
        if (compressionAlgorithm != null && !payload.isEmpty()) {
            payload.setZip(compressionAlgorithm);
            this.headerBuilder.put(DefaultHeader.COMPRESSION_ALGORITHM.getId(), compressionAlgorithm.getId());
        }

        if (Strings.hasText(payload.getContentType())) {
            // We retain the value from the content* calls to prevent accidental removal from
            // header().empty() or header().delete calls
            this.headerBuilder.contentType(payload.getContentType());
        }

        Provider keyProvider = ProviderKey.getProvider(this.key, this.provider);
        Key key = ProviderKey.getKey(this.key);
        if (jwe) {
            return encrypt(payload, key, keyProvider);
        } else if (key != null) {
            return sign(payload, key, keyProvider);
        } else {
            return unprotected(payload);
        }
    }

    // automatically closes the OutputStream
    private void writeAndClose(String name, Map<String, ?> map, OutputStream out) {
        try {
            Serializer<Map<String, ?>> named = new NamedSerializer(name, this.serializer);
            named.serialize(map, out);
        } finally {
            Objects.nullSafeClose(out);
        }
    }

    private void writeAndClose(String name, final Payload payload, OutputStream out) {
        out = payload.compress(out); // compression if necessary
        if (payload.isClaims()) {
            writeAndClose(name, payload.getRequiredClaims(), out);
        } else {
            try {
                InputStream in = payload.toInputStream();
                Streams.copy(in, out, new byte[4096], "Unable to copy payload.");
            } finally {
                Objects.nullSafeClose(out);
            }
        }
    }

    private String sign(final Payload payload, final Key key, final Provider provider) {

        Assert.stateNotNull(key, "Key is required."); // set by signWithWith*
        Assert.stateNotNull(sigAlg, "SignatureAlgorithm is required."); // invariant
        Assert.stateNotNull(signFunction, "Signature Algorithm function cannot be null.");
        Assert.stateNotNull(payload, "Payload argument cannot be null.");

        final ByteArrayOutputStream jws = new ByteArrayOutputStream(4096);

        // ----- header -----
        this.headerBuilder.add(DefaultHeader.ALGORITHM.getId(), sigAlg.getId());
        if (!this.encodePayload) { // b64 extension:
            String id = DefaultJwsHeader.B64.getId();
            this.headerBuilder.critical().add(id).and().add(id, false);
        }
        final JwsHeader header = Assert.isInstanceOf(JwsHeader.class, this.headerBuilder.build());
        encodeAndWrite("JWS Protected Header", header, jws);

        // ----- separator -----
        jws.write(DefaultJwtParser.SEPARATOR_CHAR);

        // ----- payload -----
        // Logic defined by table in https://datatracker.ietf.org/doc/html/rfc7797#section-3 :
        InputStream signingInput;
        InputStream payloadStream = null; // not needed unless b64 is enabled
        if (this.encodePayload) {
            encodeAndWrite("JWS Payload", payload, jws);
            signingInput = Streams.of(jws.toByteArray());
        } else { // b64

            // First, ensure we have the base64url header bytes + the SEPARATOR_CHAR byte:
            InputStream prefixStream = Streams.of(jws.toByteArray());

            // Next, b64 extension requires the raw (non-encoded) payload to be included directly in the signing input,
            // so we ensure we have an input stream for that:
            payloadStream = toInputStream("JWS Unencoded Payload", payload);

            if (!payload.isClaims()) {
                payloadStream = new CountingInputStream(payloadStream); // we'll need to assert if it's empty later
            }
            if (payloadStream.markSupported()) {
                payloadStream.mark(0); // to rewind
            }

            // (base64url header bytes + separator char) + raw payload bytes:
            // and don't let the SequenceInputStream close the payloadStream in case reset is needed:
            signingInput = new SequenceInputStream(prefixStream, new UncloseableInputStream(payloadStream));
        }

        byte[] signature;
        try {
            SecureRequest<InputStream, Key> request = new DefaultSecureRequest<>(signingInput, provider, secureRandom, key);
            signature = signFunction.apply(request);

            // now that we've calculated the signature, if using the b64 extension, and the payload is
            // attached ('non-detached'), we need to include it in the jws before the signature token.
            // (Note that if encodePayload is true, the payload has already been written to jws at this point, so
            // we only need to write if encodePayload is false and the payload is attached):
            if (!this.encodePayload) {
                if (!payload.isCompressed() // don't print raw compressed bytes
                        && (payload.isClaims() || payload.isString())) {
                    // now add the payload to the jws output:
                    Streams.copy(payloadStream, jws, new byte[8192], "Unable to copy attached Payload InputStream.");
                }
                if (payloadStream instanceof CountingInputStream && ((CountingInputStream) payloadStream).getCount() <= 0) {
                    String msg = "'b64' Unencoded payload option has been specified, but payload is empty.";
                    throw new IllegalStateException(msg);
                }
            }
        } finally {
            Streams.reset(payloadStream);
        }

        // ----- separator -----
        jws.write(DefaultJwtParser.SEPARATOR_CHAR);

        // ----- signature -----
        encodeAndWrite("JWS Signature", signature, jws);

        return Strings.utf8(jws.toByteArray());
    }

    private String unprotected(final Payload content) {

        Assert.stateNotNull(content, "Content argument cannot be null.");
        assertPayloadEncoding("unprotected JWT");

        this.headerBuilder.add(DefaultHeader.ALGORITHM.getId(), Jwts.SIG.NONE.getId());

        final ByteArrayOutputStream jwt = new ByteArrayOutputStream(512);

        // ----- header -----
        final Header header = this.headerBuilder.build();
        encodeAndWrite("JWT Header", header, jwt);

        // ----- separator -----
        jwt.write(DefaultJwtParser.SEPARATOR_CHAR);

        // ----- payload -----
        encodeAndWrite("JWT Payload", content, jwt);

        // ----- period terminator -----
        jwt.write(DefaultJwtParser.SEPARATOR_CHAR); // https://www.rfc-editor.org/rfc/rfc7519#section-6.1

        return Strings.ascii(jwt.toByteArray());
    }

    private void encrypt(final AeadRequest req, final AeadResult res) throws SecurityException {
        Function<Object, Object> fn = Functions.wrap(new Function<Object, Object>() {
            @Override
            public Object apply(Object o) {
                enc.encrypt(req, res);
                return null;
            }
        }, SecurityException.class, "%s encryption failed.", enc.getId());
        fn.apply(null);
    }

    private String encrypt(final Payload content, final Key key, final Provider keyProvider) {

        Assert.stateNotNull(content, "Payload argument cannot be null.");
        Assert.stateNotNull(key, "Key is required."); // set by encryptWith*
        Assert.stateNotNull(enc, "Encryption algorithm is required."); // set by encryptWith*
        Assert.stateNotNull(keyAlg, "KeyAlgorithm is required."); //set by encryptWith*
        Assert.stateNotNull(keyAlgFunction, "KeyAlgorithm function cannot be null.");
        assertPayloadEncoding("JWE");

        InputStream plaintext = toInputStream("JWE Payload", content);

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

        // ----- header -----
        ByteArrayOutputStream jwe = new ByteArrayOutputStream(8192);
        encodeAndWrite("JWE Protected Header", header, jwe);

        // JWE RFC requires AAD to be the ASCII bytes of the Base64URL-encoded header. Since the header bytes are
        // already Base64URL-encoded at this point (via the encoder.wrap call just above), and Base64Url-encoding uses
        // only ASCII characters, we don't need to use StandardCharsets.US_ASCII to explicitly convert here - just
        // use the already-encoded (ascii) bytes:
        InputStream aad = Streams.of(jwe.toByteArray());

        // During encryption, the configured Provider applies to the KeyAlgorithm, not the AeadAlgorithm, mostly
        // because all JVMs support the standard AeadAlgorithms (especially with BouncyCastle in the classpath).
        // As such, the provider here is intentionally omitted (null):
        // TODO: add encProvider(Provider) builder method that applies to this request only?
        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream(8192);
        AeadRequest req = new DefaultAeadRequest(plaintext, null, secureRandom, cek, aad);
        DefaultAeadResult res = new DefaultAeadResult(ciphertextOut);
        encrypt(req, res);

        byte[] iv = Assert.notEmpty(res.getIv(), "Encryption result must have a non-empty initialization vector.");
        byte[] tag = Assert.notEmpty(res.getDigest(), "Encryption result must have a non-empty authentication tag.");
        byte[] ciphertext = Assert.notEmpty(ciphertextOut.toByteArray(), "Encryption result must have non-empty ciphertext.");

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        encodeAndWrite("JWE Encrypted CEK", encryptedCek, jwe);

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        encodeAndWrite("JWE Initialization Vector", iv, jwe);

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        encodeAndWrite("JWE Ciphertext", ciphertext, jwe);

        jwe.write(DefaultJwtParser.SEPARATOR_CHAR);
        encodeAndWrite("JWE AAD Tag", tag, jwe);

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

    private OutputStream encode(OutputStream out, String name) {
        out = this.encoder.encode(out);
        return new EncodingOutputStream(out, "base64url", name);
    }

    private void encodeAndWrite(String name, Map<String, ?> map, OutputStream out) {
        out = encode(out, name);
        writeAndClose(name, map, out);
    }

    private void encodeAndWrite(String name, Payload payload, OutputStream out) {
        out = encode(out, name);
        writeAndClose(name, payload, out);
    }

    private void encodeAndWrite(String name, byte[] data, OutputStream out) {
        out = encode(out, name);
        Streams.writeAndClose(out, data, "Unable to write bytes");
    }

    private InputStream toInputStream(final String name, Payload payload) {
        if (payload.isClaims() || payload.isCompressed()) {
            ByteArrayOutputStream claimsOut = new ByteArrayOutputStream(8192);
            writeAndClose(name, payload, claimsOut);
            return Streams.of(claimsOut.toByteArray());
        } else {
            // No claims and not compressed, so just get the direct InputStream:
            return Assert.stateNotNull(payload.toInputStream(), "Payload InputStream cannot be null.");
        }
    }

}

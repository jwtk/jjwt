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
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.impl.lang.PropagatingExceptionFunction;
import io.jsonwebtoken.impl.security.DefaultSignatureRequest;
import io.jsonwebtoken.impl.security.SignatureAlgorithmsBridge;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
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

@SuppressWarnings("unchecked")
public class DefaultJwtBuilder<T extends JwtBuilder<T>> implements JwtBuilder<T> {

    protected Provider provider;
    protected SecureRandom secureRandom;

    protected Header<?> header;
    protected Claims claims;
    protected String payload;

    private SignatureAlgorithm<Key,?> algorithm = SignatureAlgorithms.NONE;
    private Function<SignatureRequest<Key>, byte[]> signFunction;

    private Key key;

    protected Serializer<Map<String, ?>> serializer;
    protected Function<Map<String,?>, byte[]> headerSerializer;
    protected Function<Map<String,?>, byte[]> claimsSerializer;

    protected Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
    protected CompressionCodec compressionCodec;

    @Override
    public T setProvider(Provider provider) {
        this.provider = provider;
        return (T)this;
    }

    @Override
    public T setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return (T)this;
    }

    @SuppressWarnings("rawtypes")
    protected Function<Map<String,?>, byte[]> wrap(final Serializer<Map<String,?>> serializer, String which) {
        // TODO for 1.0 - these should throw SerializationException not IllegalArgumentException
        // IAE is being retained for backwards pre-1.0 behavior compatibility
        Class clazz = "header".equals(which) ? IllegalStateException.class : IllegalArgumentException.class;
        return new PropagatingExceptionFunction<>(clazz,
            "Unable to serialize " + which + " to JSON.",
            new Function<Map<String, ?>, byte[]>() {
                @Override
                public byte[] apply(Map<String, ?> map) {
                    return serializer.serialize(map);
                }
            }
        );
    }

    @Override
    public T serializeToJsonWith(final Serializer<Map<String, ?>> serializer) {
        Assert.notNull(serializer, "Serializer cannot be null.");
        this.serializer = serializer;
        this.headerSerializer = wrap(serializer, "header");
        this.claimsSerializer = wrap(serializer, "claims");
        return (T)this;
    }

    @Override
    public T base64UrlEncodeWith(Encoder<byte[], String> base64UrlEncoder) {
        Assert.notNull(base64UrlEncoder, "base64UrlEncoder cannot be null.");
        this.base64UrlEncoder = base64UrlEncoder;
        return (T)this;
    }

    @Override
    public T setHeader(Header<?> header) {
        this.header = header;
        return (T)this;
    }

    @Override
    public T setHeader(Map<String, ?> header) {
        this.header = new DefaultHeader<>(header);
        return (T)this;
    }

    @Override
    public T setHeaderParams(Map<String, ?> params) {
        if (!Collections.isEmpty(params)) {
            Header<?> header = ensureHeader();
            header.putAll(params);
        }
        return (T)this;
    }

    protected Header<?> ensureHeader() {
        if (this.header == null) {
            this.header = new DefaultHeader<>();
        }
        return this.header;
    }

    @Override
    public T setHeaderParam(String name, Object value) {
        ensureHeader().put(name, value);
        return (T)this;
    }

    @Override
    public T signWith(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        SignatureAlgorithm<Key,?> alg = (SignatureAlgorithm<Key,?>)SignatureAlgorithms.forSigningKey(key);
        return signWith(key, alg);
    }

    @Override
    public <K extends Key> T signWith(K key, final SignatureAlgorithm<K,?> alg) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        this.key = key;
        this.algorithm = (SignatureAlgorithm<Key,?>)alg;
        this.signFunction = new PropagatingExceptionFunction<>(SignatureException.class,
            "Unable to compute " + alg.getId() + " signature.", new Function<SignatureRequest<Key>, byte[]>() {
            @Override
            public byte[] apply(SignatureRequest<Key> request) {
                return algorithm.sign(request);
            }
        });
        return (T)this;
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public T signWith(Key key, io.jsonwebtoken.SignatureAlgorithm alg) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        alg.assertValidSigningKey(key); //since 0.10.0 for https://github.com/jwtk/jjwt/issues/334
        return signWith(key, (SignatureAlgorithm<Key,?>)SignatureAlgorithmsBridge.forId(alg.getValue()));
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public T signWith(io.jsonwebtoken.SignatureAlgorithm alg, byte[] secretKeyBytes) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notEmpty(secretKeyBytes, "secret key byte array cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        SecretKey key = new SecretKeySpec(secretKeyBytes, alg.getJcaName());
        return signWith(key, alg);
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public T signWith(io.jsonwebtoken.SignatureAlgorithm alg, String base64EncodedSecretKey) throws InvalidKeyException {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return signWith(alg, bytes);
    }

    @SuppressWarnings("deprecation") // TODO: remove method for 1.0
    @Override
    public T signWith(io.jsonwebtoken.SignatureAlgorithm alg, Key key) {
        return signWith(key, alg);
    }

    @Override
    public T compressWith(CompressionCodec compressionCodec) {
        Assert.notNull(compressionCodec, "compressionCodec cannot be null");
        this.compressionCodec = compressionCodec;
        return (T)this;
    }

    @Override
    public T setPayload(String payload) {
        this.payload = payload;
        return (T)this;
    }

    protected Claims ensureClaims() {
        if (this.claims == null) {
            this.claims = new DefaultClaims();
        }
        return this.claims;
    }

    @Override
    public T setClaims(Claims claims) {
        this.claims = claims;
        return (T)this;
    }

    @Override
    public T setClaims(Map<String, ?> claims) {
        this.claims = new DefaultClaims(claims);
        return (T)this;
    }

    @Override
    public T addClaims(Map<String, ?> claims) {
        ensureClaims().putAll(claims);
        return (T)this;
    }

    @Override
    public T setIssuer(String iss) {
        if (Strings.hasText(iss)) {
            ensureClaims().setIssuer(iss);
        } else {
            if (this.claims != null) {
                claims.setIssuer(iss);
            }
        }
        return (T)this;
    }

    @Override
    public T setSubject(String sub) {
        if (Strings.hasText(sub)) {
            ensureClaims().setSubject(sub);
        } else {
            if (this.claims != null) {
                claims.setSubject(sub);
            }
        }
        return (T)this;
    }

    @Override
    public T setAudience(String aud) {
        if (Strings.hasText(aud)) {
            ensureClaims().setAudience(aud);
        } else {
            if (this.claims != null) {
                claims.setAudience(aud);
            }
        }
        return (T)this;
    }

    @Override
    public T setExpiration(Date exp) {
        if (exp != null) {
            ensureClaims().setExpiration(exp);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setExpiration(exp);
            }
        }
        return (T)this;
    }

    @Override
    public T setNotBefore(Date nbf) {
        if (nbf != null) {
            ensureClaims().setNotBefore(nbf);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setNotBefore(nbf);
            }
        }
        return (T)this;
    }

    @Override
    public T setIssuedAt(Date iat) {
        if (iat != null) {
            ensureClaims().setIssuedAt(iat);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setIssuedAt(iat);
            }
        }
        return (T)this;
    }

    @Override
    public T setId(String jti) {
        if (Strings.hasText(jti)) {
            ensureClaims().setId(jti);
        } else {
            if (this.claims != null) {
                claims.setId(jti);
            }
        }
        return (T)this;
    }

    @Override
    public T claim(String name, Object value) {
        Assert.hasText(name, "Claim property name cannot be null or empty.");
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

        return (T)this;
    }

    @Override
    public String compact() {

        if (this.serializer == null) {
            // try to find one based on the services available
            // TODO: This util class will throw a UnavailableImplementationException here to retain behavior of previous version, remove in v1.0
            // use the previous commented out line instead
            //noinspection deprecation
            serializeToJsonWith(LegacyServices.loadFirst(Serializer.class));
        }

        if (payload == null && Collections.isEmpty(claims)) {
            payload = "";
        }

        if (payload != null && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'payload' and 'claims' cannot both be specified. Choose either one.");
        }

        Header<?> header = ensureHeader();

        JwsHeader jwsHeader;
        if (header instanceof JwsHeader) {
            jwsHeader = (JwsHeader) header;
        } else {
            header = jwsHeader = new DefaultJwsHeader(header);
        }

        Assert.state(algorithm != null, "algorithm instance should never be null."); // invariant
        jwsHeader.setAlgorithm(algorithm.getId());

        byte[] bytes = this.payload != null ? payload.getBytes(Strings.UTF_8) : claimsSerializer.apply(claims);

        if (Arrays.length(bytes) > 0 && compressionCodec != null) {
            header.setCompressionAlgorithm(compressionCodec.getAlgorithmName());
            bytes = compressionCodec.compress(bytes);
        }

        byte[] headerBytes = headerSerializer.apply(jwsHeader);
        String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        String base64UrlEncodedBody = base64UrlEncoder.encode(bytes);

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;

        if (key != null) { //jwt must be signed:
            byte[] data = jwt.getBytes(StandardCharsets.US_ASCII);
            SignatureRequest<Key> request = new DefaultSignatureRequest<>(provider, secureRandom, data, key);
            byte[] signature = signFunction.apply(request);
            String base64UrlSignature = base64UrlEncoder.encode(signature);
            jwt += JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (plaintext), but must terminate w/ a period, see
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1
            jwt += JwtParser.SEPARATOR_CHAR;
        }

        return jwt;
    }
}

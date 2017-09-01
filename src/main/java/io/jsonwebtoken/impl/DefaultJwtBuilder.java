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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.Map;

public class DefaultJwtBuilder implements JwtBuilder {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private Header header;
    private Claims claims;
    private String payload;

    private SignatureAlgorithm algorithm;
    private Key                key;
    private byte[]             keyBytes;

    private CompressionCodec compressionCodec;

    @Override
    public JwtBuilder setHeader(Header header) {
        this.header = header;
        return this;
    }

    @Override
    public JwtBuilder setHeader(Map<String, Object> header) {
        this.header = new DefaultHeader(header);
        return this;
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, Object> params) {
        if (!Collections.isEmpty(params)) {

            Header header = ensureHeader();

            for (Map.Entry<String, Object> entry : params.entrySet()) {
                header.put(entry.getKey(), entry.getValue());
            }
        }
        return this;
    }

    protected Header ensureHeader() {
        if (this.header == null) {
            this.header = new DefaultHeader();
        }
        return this.header;
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        ensureHeader().put(name, value);
        return this;
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, byte[] secretKey) {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notEmpty(secretKey, "secret key byte array cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        this.algorithm = alg;
        this.keyBytes = secretKey;
        return this;
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        byte[] bytes = TextCodec.BASE64.decode(base64EncodedSecretKey);
        return signWith(alg, bytes);
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, Key key) {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notNull(key, "Key argument cannot be null.");
        this.algorithm = alg;
        this.key = key;
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
    public JwtBuilder setClaims(Map<String, Object> claims) {
        this.claims = Jwts.claims(claims);
        return this;
    }

    @Override
    public JwtBuilder addClaims(Map<String, Object> claims) {
        ensureClaims().putAll(claims);
        return this;
    }

    @Override
    public JwtBuilder setIssuer(String iss) {
        if (Strings.hasText(iss)) {
            ensureClaims().setIssuer(iss);
        } else {
            if (this.claims != null) {
                claims.setIssuer(iss);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setSubject(String sub) {
        if (Strings.hasText(sub)) {
            ensureClaims().setSubject(sub);
        } else {
            if (this.claims != null) {
                claims.setSubject(sub);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        if (Strings.hasText(aud)) {
            ensureClaims().setAudience(aud);
        } else {
            if (this.claims != null) {
                claims.setAudience(aud);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        if (exp != null) {
            ensureClaims().setExpiration(exp);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setExpiration(exp);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        if (nbf != null) {
            ensureClaims().setNotBefore(nbf);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setNotBefore(nbf);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        if (iat != null) {
            ensureClaims().setIssuedAt(iat);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setIssuedAt(iat);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setId(String jti) {
        if (Strings.hasText(jti)) {
            ensureClaims().setId(jti);
        } else {
            if (this.claims != null) {
                claims.setId(jti);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder claim(String name, Object value) {
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

        return this;
    }

    @Override
    public String compact() {
        if (payload == null && Collections.isEmpty(claims)) {
            throw new IllegalStateException("Either 'payload' or 'claims' must be specified.");
        }

        if (payload != null && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'payload' and 'claims' cannot both be specified. Choose either one.");
        }

        if (key != null && keyBytes != null) {
            throw new IllegalStateException("A key object and key bytes cannot both be specified. Choose either one.");
        }

        Header header = ensureHeader();

        Key key = this.key;
        if (key == null && !Objects.isEmpty(keyBytes)) {
            key = new SecretKeySpec(keyBytes, algorithm.getJcaName());
        }

        JwsHeader jwsHeader;

        if (header instanceof JwsHeader) {
            jwsHeader = (JwsHeader)header;
        } else {
            jwsHeader = new DefaultJwsHeader(header);
        }

        if (key != null) {
            jwsHeader.setAlgorithm(algorithm.getValue());
        } else {
            //no signature - plaintext JWT:
            jwsHeader.setAlgorithm(SignatureAlgorithm.NONE.getValue());
        }

        if (compressionCodec != null) {
            jwsHeader.setCompressionAlgorithm(compressionCodec.getAlgorithmName());
        }

        String base64UrlEncodedHeader = base64UrlEncode(jwsHeader, "Unable to serialize header to json.");

        String base64UrlEncodedBody;

        if (compressionCodec != null) {

            byte[] bytes;
            try {
                bytes = this.payload != null ? payload.getBytes(Strings.UTF_8) : toJson(claims);
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Unable to serialize claims object to json.");
            }

            base64UrlEncodedBody = TextCodec.BASE64URL.encode(compressionCodec.compress(bytes));

        } else {
            base64UrlEncodedBody = this.payload != null ?
                    TextCodec.BASE64URL.encode(this.payload) :
                    base64UrlEncode(claims, "Unable to serialize claims object to json.");
        }

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;

        if (key != null) { //jwt must be signed:

            JwtSigner signer = createSigner(algorithm, key);

            String base64UrlSignature = signer.sign(jwt);

            jwt += JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (plaintext), but must terminate w/ a period, see
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1
            jwt += JwtParser.SEPARATOR_CHAR;
        }

        return jwt;
    }

    /*
     * @since 0.5 mostly to allow testing overrides
     */
    protected JwtSigner createSigner(SignatureAlgorithm alg, Key key) {
        return new DefaultJwtSigner(alg, key);
    }

    protected String base64UrlEncode(Object o, String errMsg) {
        byte[] bytes;
        try {
            bytes = toJson(o);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(errMsg, e);
        }

        return TextCodec.BASE64URL.encode(bytes);
    }


    protected byte[] toJson(Object object) throws  JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsBytes(object);
    }
}

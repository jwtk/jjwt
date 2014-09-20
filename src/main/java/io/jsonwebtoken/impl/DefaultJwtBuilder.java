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
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultJwtBuilder implements JwtBuilder {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private Header header;
    private Claims claims;
    private String payload;

    private SignatureAlgorithm algorithm;
    private Key                key;
    private byte[]             keyBytes;

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
        Assert.isTrue(!alg.isRsa(), "Key bytes cannot be specified for RSA signatures.  Please specify an RSA PrivateKey instance.");
        this.algorithm = alg;
        this.keyBytes = secretKey;
        return this;
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
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
    public JwtBuilder setPayload(String payload) {
        this.payload = payload;
        return this;
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
    public String compact() {
        if (payload == null && claims == null) {
            throw new IllegalStateException("Either 'payload' or 'claims' must be specified.");
        }

        if (payload != null && claims != null) {
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

        String base64UrlEncodedHeader = base64UrlEncode(jwsHeader, "Unable to serialize header to json.");

        String base64UrlEncodedBody = this.payload != null ?
                                      TextCodec.BASE64URL.encode(this.payload) :
                                      base64UrlEncode(claims, "Unable to serialize claims object to json.");

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;

        if (key != null) { //jwt must be signed:

            JwtSigner signer = new DefaultJwtSigner(algorithm, key);

            String base64UrlSignature = signer.sign(jwt);

            jwt += JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (plaintext), but must terminate w/ a period, see
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1
            jwt += JwtParser.SEPARATOR_CHAR;
        }

        return jwt;
    }

    public static String base64UrlEncode(Object o, String errMsg) {
        String s;
        try {
            s = OBJECT_MAPPER.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(errMsg, e);
        }

        return TextCodec.BASE64URL.encode(s);
    }
}

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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;
import io.jsonwebtoken.impl.crypto.JwtSignatureValidator;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultJwtParser implements JwtParser {

    //don't need millis since JWT date fields are only second granularity:
    private static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ssZ";

    private ObjectMapper objectMapper = new ObjectMapper();

    private byte[] keyBytes;

    private Key key;

    private SigningKeyResolver signingKeyResolver;

    @Override
    public JwtParser setSigningKey(byte[] key) {
        Assert.notEmpty(key, "signing key cannot be null or empty.");
        this.keyBytes = key;
        return this;
    }

    @Override
    public JwtParser setSigningKey(String base64EncodedKeyBytes) {
        Assert.hasText(base64EncodedKeyBytes, "signing key cannot be null or empty.");
        this.keyBytes = TextCodec.BASE64.decode(base64EncodedKeyBytes);
        return this;
    }

    @Override
    public JwtParser setSigningKey(Key key) {
        Assert.notNull(key, "signing key cannot be null.");
        this.key = key;
        return this;
    }

    @Override
    public JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.signingKeyResolver = signingKeyResolver;
        return this;
    }

    @Override
    public boolean isSigned(String jwt) {

        if (jwt == null) {
            return false;
        }

        int delimiterCount = 0;

        for (int i = 0; i < jwt.length(); i++) {
            char c = jwt.charAt(i);

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
    public Jwt parse(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException {

        Assert.hasText(jwt, "JWT String argument cannot be null or empty.");

        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;

        int delimiterCount = 0;

        StringBuilder sb = new StringBuilder(128);

        for (char c : jwt.toCharArray()) {

            if (c == SEPARATOR_CHAR) {

                String token = Strings.clean(sb.toString());

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedPayload = token;
                }

                delimiterCount++;
                sb = new StringBuilder(128);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }
        if (sb.length() > 0) {
            base64UrlEncodedDigest = sb.toString();
        }

        if (base64UrlEncodedPayload == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a body/payload.");
        }

        // =============== Header =================
        Header header = null;

        if (base64UrlEncodedHeader != null) {
            String origValue = TextCodec.BASE64URL.decodeToString(base64UrlEncodedHeader);
            Map<String, Object> m = readValue(origValue);

            if (base64UrlEncodedDigest != null) {
                header = new DefaultJwsHeader(m);
            } else {
                header = new DefaultHeader(m);
            }
        }

        // =============== Body =================
        String payload = TextCodec.BASE64URL.decodeToString(base64UrlEncodedPayload);

        Claims claims = null;

        if (payload.charAt(0) == '{' && payload.charAt(payload.length() - 1) == '}') { //likely to be json, parse it:
            Map<String, Object> claimsMap = readValue(payload);
            claims = new DefaultClaims(claimsMap);
        }

        //since 0.3:
        if (claims != null) {

            Date now = null;
            SimpleDateFormat sdf;

            //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1.4
            //token MUST NOT be accepted on or after any specified exp time:
            Date exp = claims.getExpiration();
            if (exp != null) {

                now = new Date();

                if (now.equals(exp) || now.after(exp)) {
                    sdf = new SimpleDateFormat(ISO_8601_FORMAT);
                    String expVal = sdf.format(exp);
                    String nowVal = sdf.format(now);

                    String msg = "JWT expired at " + expVal + ". Current time: " + nowVal;
                    throw new ExpiredJwtException(msg);
                }
            }

            //https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1.5
            //token MUST NOT be accepted before any specified nbf time:
            Date nbf = claims.getNotBefore();
            if (nbf != null) {

                if (now == null) {
                    now = new Date();
                }

                if (now.before(nbf)) {
                    sdf = new SimpleDateFormat(ISO_8601_FORMAT);
                    String nbfVal = sdf.format(nbf);
                    String nowVal = sdf.format(now);

                    String msg = "JWT must not be accepted before " + nbfVal + ". Current time: " + nowVal;
                    throw new PrematureJwtException(msg);
                }
            }
        }

        // =============== Signature =================
        if (base64UrlEncodedDigest != null) { //it is signed - validate the signature

            JwsHeader jwsHeader = (JwsHeader) header;

            SignatureAlgorithm algorithm = null;

            if (header != null) {
                String alg = jwsHeader.getAlgorithm();
                if (Strings.hasText(alg)) {
                    algorithm = SignatureAlgorithm.forName(alg);
                }
            }

            if (algorithm == null || algorithm == SignatureAlgorithm.NONE) {
                //it is plaintext, but it has a signature.  This is invalid:
                String msg = "JWT string has a digest/signature, but the header does not reference a valid signature " +
                             "algorithm.";
                throw new MalformedJwtException(msg);
            }

            if (key != null && keyBytes != null) {
                throw new IllegalStateException("A key object and key bytes cannot both be specified. Choose either.");
            } else if ((key != null || keyBytes != null) && signingKeyResolver != null) {
                String object = key != null ? "a key object" : "key bytes";
                throw new IllegalStateException("A signing key resolver and " + object + " cannot both be specified. Choose either.");
            }

            //digitally signed, let's assert the signature:
            Key key = this.key;

            if (key == null) { //fall back to keyBytes

                byte[] keyBytes = this.keyBytes;

                if (Objects.isEmpty(keyBytes) && signingKeyResolver != null) { //use the signingKeyResolver
                    if (claims != null) {
                        key = signingKeyResolver.resolveSigningKey(jwsHeader, claims);
                    } else {
                        key = signingKeyResolver.resolveSigningKey(jwsHeader, payload);
                    }
                }

                if (!Objects.isEmpty(keyBytes)) {

                    Assert.isTrue(!algorithm.isRsa(),
                                  "Key bytes cannot be specified for RSA signatures.  Please specify a PublicKey or PrivateKey instance.");

                    key = new SecretKeySpec(keyBytes, algorithm.getJcaName());
                }
            }

            Assert.notNull(key, "A signing key must be specified if the specified JWT is digitally signed.");

            //re-create the jwt part without the signature.  This is what needs to be signed for verification:
            String jwtWithoutSignature = base64UrlEncodedHeader + SEPARATOR_CHAR + base64UrlEncodedPayload;

            JwtSignatureValidator validator = new DefaultJwtSignatureValidator(algorithm, key);

            if (!validator.isValid(jwtWithoutSignature, base64UrlEncodedDigest)) {
                String msg = "JWT signature does not match locally computed signature. JWT validity cannot be " +
                             "asserted and should not be trusted.";
                throw new SignatureException(msg);
            }
        }

        Object body = claims != null ? claims : payload;

        if (base64UrlEncodedDigest != null) {
            return new DefaultJws<Object>((JwsHeader) header, body, base64UrlEncodedDigest);
        } else {
            return new DefaultJwt<Object>(header, body);
        }
    }

    @Override
    public <T> T parse(String compact, JwtHandler<T> handler)
        throws ExpiredJwtException, MalformedJwtException, SignatureException {
        Assert.notNull(handler, "JwtHandler argument cannot be null.");
        Assert.hasText(compact, "JWT String argument cannot be null or empty.");

        Jwt jwt = parse(compact);

        if (jwt instanceof Jws) {
            Jws jws = (Jws) jwt;
            Object body = jws.getBody();
            if (body instanceof Claims) {
                return handler.onClaimsJws((Jws<Claims>) jws);
            } else {
                return handler.onPlaintextJws((Jws<String>) jws);
            }
        } else {
            Object body = jwt.getBody();
            if (body instanceof Claims) {
                return handler.onClaimsJwt((Jwt<Header, Claims>) jwt);
            } else {
                return handler.onPlaintextJwt((Jwt<Header, String>) jwt);
            }
        }
    }

    @Override
    public Jwt<Header, String> parsePlaintextJwt(String plaintextJwt) {
        return parse(plaintextJwt, new JwtHandlerAdapter<Jwt<Header, String>>() {
            @Override
            public Jwt<Header, String> onPlaintextJwt(Jwt<Header, String> jwt) {
                return jwt;
            }
        });
    }

    @Override
    public Jwt<Header, Claims> parseClaimsJwt(String claimsJwt) {
        try {
            return parse(claimsJwt, new JwtHandlerAdapter<Jwt<Header, Claims>>() {
                @Override
                public Jwt<Header, Claims> onClaimsJwt(Jwt<Header, Claims> jwt) {
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

    @SuppressWarnings("unchecked")
    protected Map<String, Object> readValue(String val) {
        try {
            return objectMapper.readValue(val, Map.class);
        } catch (IOException e) {
            throw new MalformedJwtException("Unable to read JSON value: " + val, e);
        }
    }
}

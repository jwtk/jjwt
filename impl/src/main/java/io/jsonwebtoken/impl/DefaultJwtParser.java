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

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.InvalidClaimException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;
import io.jsonwebtoken.impl.crypto.JwtSignatureValidator;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@SuppressWarnings("unchecked")
public class DefaultJwtParser implements JwtParser {

    private static final int MILLISECONDS_PER_SECOND = 1000;

    // TODO: make the folling fields final for v1.0
    private byte[] keyBytes;

    private Key key;

    private SigningKeyResolver signingKeyResolver;

    private CompressionCodecResolver compressionCodecResolver = new DefaultCompressionCodecResolver();

    private Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;

    private Deserializer<Map<String, ?>> deserializer;

    private Claims expectedClaims = new DefaultClaims();

    private Clock clock = DefaultClock.INSTANCE;

    private long allowedClockSkewMillis = 0;

    /**
     * TODO: remove this constructor before 1.0
     * @deprecated for backward compatibility only, see other constructors.
     */
    @Deprecated
    public DefaultJwtParser() { }

    DefaultJwtParser(SigningKeyResolver signingKeyResolver,
                     Key key,
                     byte[] keyBytes,
                     Clock clock,
                     long allowedClockSkewMillis,
                     Claims expectedClaims,
                     Decoder<String, byte[]> base64UrlDecoder,
                     Deserializer<Map<String, ?>> deserializer,
                     CompressionCodecResolver compressionCodecResolver) {
        this.signingKeyResolver = signingKeyResolver;
        this.key = key;
        this.keyBytes = keyBytes;
        this.clock = clock;
        this.allowedClockSkewMillis = allowedClockSkewMillis;
        this.expectedClaims = expectedClaims;
        this.base64UrlDecoder = base64UrlDecoder;
        this.deserializer = deserializer;
        this.compressionCodecResolver = compressionCodecResolver;
    }

    @Override
    public JwtParser deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        Assert.notNull(deserializer, "deserializer cannot be null.");
        this.deserializer = deserializer;
        return this;
    }

    @Override
    public JwtParser base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder) {
        Assert.notNull(base64UrlDecoder, "base64UrlDecoder cannot be null.");
        this.base64UrlDecoder = base64UrlDecoder;
        return this;
    }

    @Override
    public JwtParser requireIssuedAt(Date issuedAt) {
        expectedClaims.setIssuedAt(issuedAt);
        return this;
    }

    @Override
    public JwtParser requireIssuer(String issuer) {
        expectedClaims.setIssuer(issuer);
        return this;
    }

    @Override
    public JwtParser requireAudience(String audience) {
        expectedClaims.setAudience(audience);
        return this;
    }

    @Override
    public JwtParser requireSubject(String subject) {
        expectedClaims.setSubject(subject);
        return this;
    }

    @Override
    public JwtParser requireId(String id) {
        expectedClaims.setId(id);
        return this;
    }

    @Override
    public JwtParser requireExpiration(Date expiration) {
        expectedClaims.setExpiration(expiration);
        return this;
    }

    @Override
    public JwtParser requireNotBefore(Date notBefore) {
        expectedClaims.setNotBefore(notBefore);
        return this;
    }

    @Override
    public JwtParser require(String claimName, Object value) {
        Assert.hasText(claimName, "claim name cannot be null or empty.");
        Assert.notNull(value, "The value cannot be null for claim name: " + claimName);
        expectedClaims.put(claimName, value);
        return this;
    }

    @Override
    public JwtParser setClock(Clock clock) {
        Assert.notNull(clock, "Clock instance cannot be null.");
        this.clock = clock;
        return this;
    }

    @Override
    public JwtParser setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException {
        Assert.isTrue(seconds <= DefaultJwtParserBuilder.MAX_CLOCK_SKEW_MILLIS, DefaultJwtParserBuilder.MAX_CLOCK_SKEW_ILLEGAL_MSG);
        this.allowedClockSkewMillis = Math.max(0, seconds * MILLISECONDS_PER_SECOND);
        return this;
    }

    @Override
    public JwtParser setSigningKey(byte[] key) {
        Assert.notEmpty(key, "signing key cannot be null or empty.");
        this.keyBytes = key;
        return this;
    }

    @Override
    public JwtParser setSigningKey(String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "signing key cannot be null or empty.");
        this.keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
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
    public JwtParser setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver) {
        Assert.notNull(compressionCodecResolver, "compressionCodecResolver cannot be null.");
        this.compressionCodecResolver = compressionCodecResolver;
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

        // TODO, this logic is only need for a now deprecated code path
        // remove this block in v1.0 (the equivalent is already in DefaultJwtParserBuilder)
        if (this.deserializer == null) {
            // try to find one based on the services available
            // TODO: This util class will throw a UnavailableImplementationException here to retain behavior of previous version, remove in v1.0
            this.deserializer = LegacyServices.loadFirst(Deserializer.class);
        }

        Assert.hasText(jwt, "JWT String argument cannot be null or empty.");

        if ("..".equals(jwt)) {
            String msg = "JWT string '..' is missing a header.";
            throw new MalformedJwtException(msg);
        }

        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;

        int delimiterCount = 0;

        StringBuilder sb = new StringBuilder(128);

        for (char c : jwt.toCharArray()) {

            if (c == SEPARATOR_CHAR) {

                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedPayload = token;
                }

                delimiterCount++;
                sb.setLength(0);
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


        // =============== Header =================
        Header header = null;

        CompressionCodec compressionCodec = null;

        if (base64UrlEncodedHeader != null) {
            byte[] bytes = base64UrlDecoder.decode(base64UrlEncodedHeader);
            String origValue = new String(bytes, Strings.UTF_8);
            Map<String, Object> m = (Map<String, Object>) readValue(origValue);

            if (base64UrlEncodedDigest != null) {
                header = new DefaultJwsHeader(m);
            } else {
                header = new DefaultHeader(m);
            }

            compressionCodec = compressionCodecResolver.resolveCompressionCodec(header);
        }

        // =============== Body =================
        String payload = ""; // https://github.com/jwtk/jjwt/pull/540
        if (base64UrlEncodedPayload != null) {
            byte[] bytes = base64UrlDecoder.decode(base64UrlEncodedPayload);
            if (compressionCodec != null) {
                bytes = compressionCodec.decompress(bytes);
            }
            payload = new String(bytes, Strings.UTF_8);
        }

        Claims claims = null;

        if (!payload.isEmpty() && payload.charAt(0) == '{' && payload.charAt(payload.length() - 1) == '}') { //likely to be json, parse it:
            Map<String, Object> claimsMap = (Map<String, Object>) readValue(payload);
            claims = new DefaultClaims(claimsMap);
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

                    Assert.isTrue(algorithm.isHmac(),
                        "Key bytes can only be specified for HMAC signatures. Please specify a PublicKey or PrivateKey instance.");

                    key = new SecretKeySpec(keyBytes, algorithm.getJcaName());
                }
            }

            Assert.notNull(key, "A signing key must be specified if the specified JWT is digitally signed.");

            //re-create the jwt part without the signature.  This is what needs to be signed for verification:
            String jwtWithoutSignature = base64UrlEncodedHeader + SEPARATOR_CHAR;
            if (base64UrlEncodedPayload != null) {
              jwtWithoutSignature += base64UrlEncodedPayload;
            }

            JwtSignatureValidator validator;
            try {
                algorithm.assertValidVerificationKey(key); //since 0.10.0: https://github.com/jwtk/jjwt/issues/334
                validator = createSignatureValidator(algorithm, key);
            } catch (WeakKeyException e) {
                throw e;
            } catch (InvalidKeyException | IllegalArgumentException e) {
                String algName = algorithm.getValue();
                String msg = "The parsed JWT indicates it was signed with the " + algName + " signature " +
                    "algorithm, but the specified signing key of type " + key.getClass().getName() +
                    " may not be used to validate " + algName + " signatures.  Because the specified " +
                    "signing key reflects a specific and expected algorithm, and the JWT does not reflect " +
                    "this algorithm, it is likely that the JWT was not expected and therefore should not be " +
                    "trusted.  Another possibility is that the parser was configured with the incorrect " +
                    "signing key, but this cannot be assumed for security reasons.";
                throw new UnsupportedJwtException(msg, e);
            }

            if (!validator.isValid(jwtWithoutSignature, base64UrlEncodedDigest)) {
                String msg = "JWT signature does not match locally computed signature. JWT validity cannot be " +
                    "asserted and should not be trusted.";
                throw new SignatureException(msg);
            }
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

                    long differenceMillis = maxTime - exp.getTime();

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

        Object body = claims != null ? claims : payload;

        if (base64UrlEncodedDigest != null) {
            return new DefaultJws<>((JwsHeader) header, body, base64UrlEncodedDigest);
        } else {
            return new DefaultJwt<>(header, body);
        }
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

        for (String expectedClaimName : expectedClaims.keySet()) {

            Object expectedClaimValue = normalize(expectedClaims.get(expectedClaimName));
            Object actualClaimValue = normalize(claims.get(expectedClaimName));

            if (expectedClaimValue instanceof Date) {
                try {
                    actualClaimValue = claims.get(expectedClaimName, Date.class);
                } catch (Exception e) {
                    String msg = "JWT Claim '" + expectedClaimName + "' was expected to be a Date, but its value " +
                        "cannot be converted to a Date using current heuristics.  Value: " + actualClaimValue;
                    throw new IncorrectClaimException(header, claims, msg);
                }
            }

            InvalidClaimException invalidClaimException = null;

            if (actualClaimValue == null) {

                String msg = String.format(ClaimJwtException.MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE,
                    expectedClaimName, expectedClaimValue);

                invalidClaimException = new MissingClaimException(header, claims, msg);

            } else if (!expectedClaimValue.equals(actualClaimValue)) {

                String msg = String.format(ClaimJwtException.INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE,
                    expectedClaimName, expectedClaimValue, actualClaimValue);

                invalidClaimException = new IncorrectClaimException(header, claims, msg);
            }

            if (invalidClaimException != null) {
                invalidClaimException.setClaimName(expectedClaimName);
                invalidClaimException.setClaimValue(expectedClaimValue);
                throw invalidClaimException;
            }
        }
    }

    /*
     * @since 0.5 mostly to allow testing overrides
     */
    protected JwtSignatureValidator createSignatureValidator(SignatureAlgorithm alg, Key key) {
        return new DefaultJwtSignatureValidator(alg, key, base64UrlDecoder);
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
    protected Map<String, ?> readValue(String val) {
        try {
            byte[] bytes = val.getBytes(Strings.UTF_8);
            return deserializer.deserialize(bytes);
        } catch (DeserializationException e) {
            throw new MalformedJwtException("Unable to read JSON value: " + val, e);
        }
    }
}

/*
 * Copyright (C) 2019 jsonwebtoken.io
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

import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.ConstantKeyLocator;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import java.security.Key;
import java.security.Provider;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * @since 0.11.0
 */
public class DefaultJwtParserBuilder implements JwtParserBuilder {

    private static final int MILLISECONDS_PER_SECOND = 1000;

    /**
     * To prevent overflow per <a href="https://github.com/jwtk/jjwt/issues/583">Issue 583</a>.
     * <p>
     * Package-protected on purpose to allow use in backwards-compatible {@link DefaultJwtParser} implementation.
     * TODO: enable private modifier on these two variables when deleting DefaultJwtParser
     */
    static final long MAX_CLOCK_SKEW_MILLIS = Long.MAX_VALUE / MILLISECONDS_PER_SECOND;
    static final String MAX_CLOCK_SKEW_ILLEGAL_MSG = "Illegal allowedClockSkewMillis value: multiplying this " +
            "value by 1000 to obtain the number of milliseconds would cause a numeric overflow.";

    private Provider provider;

    private boolean enableUnsecuredJws = false;

    private boolean enableUnsecuredDecompression = false;

    private Locator<? extends Key> keyLocator;

    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    private SigningKeyResolver signingKeyResolver = null;

    private final Collection<AeadAlgorithm> extraEncAlgs = new LinkedHashSet<>();

    private final Collection<KeyAlgorithm<?, ?>> extraKeyAlgs = new LinkedHashSet<>();

    private final Collection<SecureDigestAlgorithm<?, ?>> extraSigAlgs = new LinkedHashSet<>();

    private final Collection<CompressionAlgorithm> extraZipAlgs = new LinkedHashSet<>();

    @SuppressWarnings("deprecation")
    private CompressionCodecResolver compressionCodecResolver;

    private Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;

    private Deserializer<Map<String, ?>> deserializer;

    private final ClaimsBuilder expectedClaims = Jwts.claims();

    private Clock clock = DefaultClock.INSTANCE;

    private long allowedClockSkewMillis = 0;

    private Key signatureVerificationKey;
    private Key decryptionKey;

    @Override
    public JwtParserBuilder enableUnsecuredJws() {
        this.enableUnsecuredJws = true;
        return this;
    }

    @Override
    public JwtParserBuilder enableUnsecuredDecompression() {
        this.enableUnsecuredDecompression = true;
        return this;
    }

    @Override
    public JwtParserBuilder setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public JwtParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        Assert.notNull(deserializer, "deserializer cannot be null.");
        this.deserializer = deserializer;
        return this;
    }

    @Override
    public JwtParserBuilder base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder) {
        Assert.notNull(base64UrlDecoder, "base64UrlDecoder cannot be null.");
        this.base64UrlDecoder = base64UrlDecoder;
        return this;
    }

    @Override
    public JwtParserBuilder requireIssuedAt(Date issuedAt) {
        expectedClaims.setIssuedAt(issuedAt);
        return this;
    }

    @Override
    public JwtParserBuilder requireIssuer(String issuer) {
        expectedClaims.setIssuer(issuer);
        return this;
    }

    @Override
    public JwtParserBuilder requireAudience(String audience) {
        expectedClaims.setAudience(audience);
        return this;
    }

    @Override
    public JwtParserBuilder requireSubject(String subject) {
        expectedClaims.setSubject(subject);
        return this;
    }

    @Override
    public JwtParserBuilder requireId(String id) {
        expectedClaims.setId(id);
        return this;
    }

    @Override
    public JwtParserBuilder requireExpiration(Date expiration) {
        expectedClaims.setExpiration(expiration);
        return this;
    }

    @Override
    public JwtParserBuilder requireNotBefore(Date notBefore) {
        expectedClaims.setNotBefore(notBefore);
        return this;
    }

    @Override
    public JwtParserBuilder require(String claimName, Object value) {
        Assert.hasText(claimName, "claim name cannot be null or empty.");
        Assert.notNull(value, "The value cannot be null for claim name: " + claimName);
        expectedClaims.set(claimName, value);
        return this;
    }

    @Override
    public JwtParserBuilder setClock(Clock clock) {
        Assert.notNull(clock, "Clock instance cannot be null.");
        this.clock = clock;
        return this;
    }

    @Override
    public JwtParserBuilder setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException {
        Assert.isTrue(seconds <= MAX_CLOCK_SKEW_MILLIS, MAX_CLOCK_SKEW_ILLEGAL_MSG);
        this.allowedClockSkewMillis = Math.max(0, seconds * MILLISECONDS_PER_SECOND);
        return this;
    }

    @Override
    public JwtParserBuilder setSigningKey(byte[] key) {
        Assert.notEmpty(key, "signature verification key cannot be null or empty.");
        return setSigningKey(Keys.hmacShaKeyFor(key));
    }

    @Override
    public JwtParserBuilder setSigningKey(String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "signature verification key cannot be null or empty.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return setSigningKey(bytes);
    }

    @Override
    public JwtParserBuilder setSigningKey(final Key key) {
        return verifyWith(key);
    }

    @Override
    public JwtParserBuilder verifyWith(Key key) {
        this.signatureVerificationKey = Assert.notNull(key, "signature verification key cannot be null.");
        return this;
    }

    @Override
    public JwtParserBuilder decryptWith(final Key key) {
        this.decryptionKey = Assert.notNull(key, "decryption key cannot be null.");
        return this;
    }

    @Override
    public JwtParserBuilder addCompressionAlgorithms(Collection<? extends CompressionAlgorithm> algs) {
        Assert.notEmpty(algs, "Additional CompressionAlgorithm collection cannot be null or empty.");
        this.extraZipAlgs.addAll(algs);
        return this;
    }

    @Override
    public JwtParserBuilder addEncryptionAlgorithms(Collection<? extends AeadAlgorithm> encAlgs) {
        Assert.notEmpty(encAlgs, "Additional AeadAlgorithm collection cannot be null or empty.");
        this.extraEncAlgs.addAll(encAlgs);
        return this;
    }

    @Override
    public JwtParserBuilder addSignatureAlgorithms(Collection<? extends SecureDigestAlgorithm<?, ?>> sigAlgs) {
        Assert.notEmpty(sigAlgs, "Additional SignatureAlgorithm collection cannot be null or empty.");
        this.extraSigAlgs.addAll(sigAlgs);
        return this;
    }

    @Override
    public JwtParserBuilder addKeyAlgorithms(Collection<? extends KeyAlgorithm<?, ?>> keyAlgs) {
        Assert.notEmpty(keyAlgs, "Additional KeyAlgorithm collection cannot be null or empty.");
        this.extraKeyAlgs.addAll(keyAlgs);
        return this;
    }

    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    @Override
    public JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.signingKeyResolver = signingKeyResolver;
        return this;
    }

    @Override
    public JwtParserBuilder setKeyLocator(Locator<Key> keyLocator) {
        this.keyLocator = Assert.notNull(keyLocator, "Key locator cannot be null.");
        return this;
    }

    @SuppressWarnings("deprecation")
    @Override
    public JwtParserBuilder setCompressionCodecResolver(CompressionCodecResolver resolver) {
        this.compressionCodecResolver = Assert.notNull(resolver, "CompressionCodecResolver cannot be null.");
        return this;
    }

    @Override
    public JwtParser build() {

        // Only lookup the deserializer IF it is null. It is possible a Deserializer implementation was set
        // that is NOT exposed as a service and no other implementations are available for lookup.
        if (this.deserializer == null) {
            // try to find one based on the services available:
            //noinspection unchecked
            this.deserializer = Services.loadFirst(Deserializer.class);
        }

        if (this.signingKeyResolver != null && this.signatureVerificationKey != null) {
            String msg = "Both a 'signingKeyResolver and a 'verifyWith' key cannot be configured. " +
                    "Choose either, or prefer `keyLocator` when possible.";
            throw new IllegalStateException(msg);
        }
        if (this.keyLocator != null) {
            if (this.signatureVerificationKey != null) {
                String msg = "Both 'keyLocator' and a 'verifyWith' key cannot be configured. " +
                        "Prefer 'keyLocator' if possible.";
                throw new IllegalStateException(msg);
            }
            if (this.decryptionKey != null) {
                String msg = "Both 'keyLocator' and a 'decryptWith' key cannot be configured. " +
                        "Prefer 'keyLocator' if possible.";
                throw new IllegalStateException(msg);
            }
        }

        Locator<? extends Key> keyLocator = this.keyLocator; // user configured default, don't overwrite to ensure further build() calls work as expected
        if (keyLocator == null) {
            keyLocator = new ConstantKeyLocator(this.signatureVerificationKey, this.decryptionKey);
        }

        if (!enableUnsecuredJws && enableUnsecuredDecompression) {
            String msg = "'enableUnsecuredDecompression' is only relevant if 'enableUnsecuredJws' is also " +
                    "configured. Please read the JavaDoc of both features before enabling either " +
                    "due to their security implications.";
            throw new IllegalStateException(msg);
        }
        if (this.compressionCodecResolver != null && !Collections.isEmpty(extraZipAlgs)) {
            String msg = "Both 'addCompressionAlgorithms' and 'compressionCodecResolver' " +
                    "cannot be specified. Choose either.";
            throw new IllegalStateException(msg);
        }

        // Invariants.  If these are ever violated, it's an error in this class implementation:
        Assert.stateNotNull(keyLocator, "Key locator should never be null.");

        final DefaultClaims expClaims = (DefaultClaims) this.expectedClaims.build();

        return new DefaultJwtParser(
                provider,
                signingKeyResolver,
                enableUnsecuredJws,
                enableUnsecuredDecompression,
                keyLocator,
                clock,
                allowedClockSkewMillis,
                expClaims,
                base64UrlDecoder,
                new JwtDeserializer<>(deserializer),
                compressionCodecResolver,
                extraZipAlgs,
                extraSigAlgs,
                extraKeyAlgs,
                extraEncAlgs
        );
    }
}

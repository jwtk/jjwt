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
import io.jsonwebtoken.impl.io.DelegateStringDecoder;
import io.jsonwebtoken.impl.io.StandardCompressionAlgorithms;
import io.jsonwebtoken.impl.lang.DefaultNestedCollection;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.ConstantKeyLocator;
import io.jsonwebtoken.impl.security.StandardEncryptionAlgorithms;
import io.jsonwebtoken.impl.security.StandardKeyAlgorithms;
import io.jsonwebtoken.impl.security.StandardSecureDigestAlgorithms;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.NestedCollection;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.Set;

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

    private boolean unsecured = false;

    private boolean unsecuredDecompression = false;

    private Locator<? extends Key> keyLocator;

    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    private SigningKeyResolver signingKeyResolver = null;

    private Registry<String, AeadAlgorithm> encAlgs = Jwts.ENC.get();

    private Registry<String, KeyAlgorithm<?, ?>> keyAlgs = Jwts.KEY.get();

    private Registry<String, SecureDigestAlgorithm<?, ?>> sigAlgs = Jwts.SIG.get();

    private Registry<String, CompressionAlgorithm> zipAlgs = Jwts.ZIP.get();

    @SuppressWarnings("deprecation")
    private CompressionCodecResolver compressionCodecResolver;

    @SuppressWarnings("deprecation")
    private Decoder<InputStream, InputStream> decoder = new DelegateStringDecoder(Decoders.BASE64URL);

    private Deserializer<Map<String, ?>> deserializer;

    private final ClaimsBuilder expectedClaims = Jwts.claims();

    private Clock clock = DefaultClock.INSTANCE;

    private Set<String> critical = Collections.emptySet();

    private long allowedClockSkewMillis = 0;

    private Key signatureVerificationKey;
    private Key decryptionKey;

    @Override
    public JwtParserBuilder unsecured() {
        this.unsecured = true;
        return this;
    }

    @Override
    public JwtParserBuilder unsecuredDecompression() {
        this.unsecuredDecompression = true;
        return this;
    }

    @Override
    public JwtParserBuilder provider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public JwtParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        return json(deserializer);
    }

    @Override
    public JwtParserBuilder json(Deserializer<Map<String, ?>> reader) {
        this.deserializer = Assert.notNull(reader, "JSON Deserializer cannot be null.");
        return this;
    }

    @SuppressWarnings("deprecation")
    @Override
    public JwtParserBuilder base64UrlDecodeWith(final Decoder<CharSequence, byte[]> decoder) {
        Assert.notNull(decoder, "decoder cannot be null.");
        return b64Url(new DelegateStringDecoder(decoder));
    }

    @Override
    public JwtParserBuilder b64Url(Decoder<InputStream, InputStream> decoder) {
        Assert.notNull(decoder, "decoder cannot be null.");
        this.decoder = decoder;
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
        expectedClaims.audience().add(audience).and();
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
        expectedClaims.add(claimName, value);
        return this;
    }

    @Override
    public JwtParserBuilder setClock(Clock clock) {
        return clock(clock);
    }

    @Override
    public JwtParserBuilder clock(Clock clock) {
        Assert.notNull(clock, "Clock instance cannot be null.");
        this.clock = clock;
        return this;
    }

    @Override
    public NestedCollection<String, JwtParserBuilder> critical() {
        return new DefaultNestedCollection<String, JwtParserBuilder>(this, this.critical) {
            @Override
            protected void changed() {
                critical = Collections.asSet(getCollection());
            }
        };
    }

    @Override
    public JwtParserBuilder setAllowedClockSkewSeconds(long seconds) throws IllegalArgumentException {
        return clockSkewSeconds(seconds);
    }

    @Override
    public JwtParserBuilder clockSkewSeconds(long seconds) throws IllegalArgumentException {
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
        if (key instanceof SecretKey) {
            return verifyWith((SecretKey) key);
        } else if (key instanceof PublicKey) {
            return verifyWith((PublicKey) key);
        }
        String msg = "JWS verification key must be either a SecretKey (for MAC algorithms) or a PublicKey " +
                "(for Signature algorithms).";
        throw new InvalidKeyException(msg);
    }

    @Override
    public JwtParserBuilder verifyWith(SecretKey key) {
        return verifyWith((Key) key);
    }

    @Override
    public JwtParserBuilder verifyWith(PublicKey key) {
        return verifyWith((Key) key);
    }

    private JwtParserBuilder verifyWith(Key key) {
        if (key instanceof PrivateKey) {
            throw new IllegalArgumentException(DefaultJwtParser.PRIV_KEY_VERIFY_MSG);
        }
        this.signatureVerificationKey = Assert.notNull(key, "signature verification key cannot be null.");
        return this;
    }

    @Override
    public JwtParserBuilder decryptWith(SecretKey key) {
        return decryptWith((Key) key);
    }

    @Override
    public JwtParserBuilder decryptWith(PrivateKey key) {
        return decryptWith((Key) key);
    }

    private JwtParserBuilder decryptWith(final Key key) {
        if (key instanceof PublicKey) {
            throw new IllegalArgumentException(DefaultJwtParser.PUB_KEY_DECRYPT_MSG);
        }
        this.decryptionKey = Assert.notNull(key, "decryption key cannot be null.");
        return this;
    }

    @Override
    public NestedCollection<CompressionAlgorithm, JwtParserBuilder> zip() {
        return new DefaultNestedCollection<CompressionAlgorithm, JwtParserBuilder>(this, this.zipAlgs.values()) {
            @Override
            protected void changed() {
                zipAlgs = new IdRegistry<>(StandardCompressionAlgorithms.NAME, getCollection());
            }
        };
    }

    @Override
    public NestedCollection<AeadAlgorithm, JwtParserBuilder> enc() {
        return new DefaultNestedCollection<AeadAlgorithm, JwtParserBuilder>(this, this.encAlgs.values()) {
            @Override
            public void changed() {
                encAlgs = new IdRegistry<>(StandardEncryptionAlgorithms.NAME, getCollection());
            }
        };
    }

    @Override
    public NestedCollection<SecureDigestAlgorithm<?, ?>, JwtParserBuilder> sig() {
        return new DefaultNestedCollection<SecureDigestAlgorithm<?, ?>, JwtParserBuilder>(this, this.sigAlgs.values()) {
            @Override
            public void changed() {
                sigAlgs = new IdRegistry<>(StandardSecureDigestAlgorithms.NAME, getCollection());
            }
        };
    }

    @Override
    public NestedCollection<KeyAlgorithm<?, ?>, JwtParserBuilder> key() {
        return new DefaultNestedCollection<KeyAlgorithm<?, ?>, JwtParserBuilder>(this, this.keyAlgs.values()) {
            @Override
            public void changed() {
                keyAlgs = new IdRegistry<>(StandardKeyAlgorithms.NAME, getCollection());
            }
        };
    }

    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    @Override
    public JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.signingKeyResolver = signingKeyResolver;
        return this;
    }

    @Override
    public JwtParserBuilder keyLocator(Locator<Key> keyLocator) {
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

        if (this.deserializer == null) {
            //noinspection unchecked
            json(Services.get(Deserializer.class));
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

        if (!unsecured && unsecuredDecompression) {
            String msg = "'unsecuredDecompression' is only relevant if 'unsecured' is also " +
                    "configured. Please read the JavaDoc of both features before enabling either " +
                    "due to their security implications.";
            throw new IllegalStateException(msg);
        }
        if (this.compressionCodecResolver != null && !Jwts.ZIP.get().equals(this.zipAlgs)) {
            String msg = "Both 'zip()' and 'compressionCodecResolver' " +
                    "cannot be configured. Choose either.";
            throw new IllegalStateException(msg);
        }

        // Invariants.  If these are ever violated, it's an error in this class implementation:
        Assert.stateNotNull(keyLocator, "Key locator should never be null.");

        final DefaultClaims expClaims = (DefaultClaims) this.expectedClaims.build();

        return new DefaultJwtParser(
                provider,
                signingKeyResolver,
                unsecured,
                unsecuredDecompression,
                keyLocator,
                clock,
                critical,
                allowedClockSkewMillis,
                expClaims,
                decoder,
                deserializer,
                compressionCodecResolver,
                zipAlgs,
                sigAlgs,
                keyAlgs,
                encAlgs
        );
    }
}

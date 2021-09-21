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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import io.jsonwebtoken.impl.lang.ConstantFunction;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.LocatorFunction;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.ConstantKeyLocator;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

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

    @SuppressWarnings({"rawtypes"})
    private Function<Header, Key> keyLocator = ConstantFunction.forNull();
    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    private SigningKeyResolver signingKeyResolver = new ConstantKeyLocator<>(null, null);

    private CompressionCodecResolver compressionCodecResolver = new DefaultCompressionCodecResolver();

    private final Collection<SymmetricAeadAlgorithm> extraEncryptionAlgorithms = new LinkedHashSet<>();

    private final Collection<KeyAlgorithm<?, ?>> extraKeyAlgorithms = new LinkedHashSet<>();

    private final Collection<SignatureAlgorithm<?, ?>> extraSignatureAlgorithms = new LinkedHashSet<>();

    private Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;

    private Deserializer<Map<String, ?>> deserializer;

    private final Claims expectedClaims = new DefaultClaims();

    private Clock clock = DefaultClock.INSTANCE;

    private long allowedClockSkewMillis = 0;

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
        expectedClaims.put(claimName, value);
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
        Assert.notEmpty(key, "signing key cannot be null or empty.");
        return setSigningKey(Keys.hmacShaKeyFor(key));
    }

    @Override
    public JwtParserBuilder setSigningKey(String base64EncodedSecretKey) {
        Assert.hasText(base64EncodedSecretKey, "signing key cannot be null or empty.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return setSigningKey(bytes);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public JwtParserBuilder setSigningKey(final Key key) {
        Assert.notNull(key, "signing key cannot be null.");
        final Function<Header, Key> existing = this.keyLocator;
        this.keyLocator = new Function<Header, Key>() {
            @Override
            public Key apply(Header header) {
                return header instanceof JwsHeader ? key : existing.apply(header);
            }
        };
        return setSigningKeyResolver(new ConstantKeyLocator<>(key, null));
    }

    @SuppressWarnings("rawtypes")
    @Override
    public JwtParserBuilder decryptWith(final Key key) {
        Assert.notNull(key, "decryption key cannot be null.");
        final Function<Header, Key> existing = this.keyLocator;
        this.keyLocator = new Function<Header, Key>() {
            @Override
            public Key apply(Header header) {
                return header instanceof JweHeader ? key : existing.apply(header);
            }
        };
        return this;
    }

    @Override
    public JwtParserBuilder addEncryptionAlgorithms(Collection<SymmetricAeadAlgorithm> encAlgs) {
        Assert.notEmpty(encAlgs, "Additional EncryptionAlgorithm collection cannot be null or empty.");
        this.extraEncryptionAlgorithms.addAll(encAlgs);
        return this;
    }

    @Override
    public JwtParserBuilder addSignatureAlgorithms(Collection<SignatureAlgorithm<?, ?>> sigAlgs) {
        Assert.notEmpty(sigAlgs, "Additional SignatureAlgorithm collection cannot be null or empty.");
        this.extraSignatureAlgorithms.addAll(sigAlgs);
        return this;
    }

    @Override
    public JwtParserBuilder addKeyAlgorithms(Collection<KeyAlgorithm<?, ?>> keyAlgs) {
        Assert.notEmpty(keyAlgs, "Additional KeyAlgorithm collection cannot be null or empty.");
        this.extraKeyAlgorithms.addAll(keyAlgs);
        return this;
    }

    @SuppressWarnings("deprecation") //TODO: remove for 1.0
    @Override
    public JwtParserBuilder setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        Assert.notNull(signingKeyResolver, "SigningKeyResolver cannot be null.");
        this.signingKeyResolver = signingKeyResolver;
        return this;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Function<Header, Key> coerce(Function f) {
        return (Function<Header, Key>) f;
    }

    @Override
    public JwtParserBuilder setKeyLocator(Locator<? extends Header<?>, Key> keyLocator) {
        Assert.notNull(keyLocator, "Key locator cannot be null.");
        this.keyLocator = coerce(new LocatorFunction<>(keyLocator));
        return this;
    }

    @Override
    public JwtParserBuilder setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver) {
        Assert.notNull(compressionCodecResolver, "compressionCodecResolver cannot be null.");
        this.compressionCodecResolver = compressionCodecResolver;
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

        // Invariants.  If these are ever violated, it's an error in this class implementation
        // (we default to non-null instances, and the setters should never allow null):
        assert this.keyLocator != null : "Key locator should never be null.";
        assert this.signingKeyResolver != null : "SigningKeyResolver should never be null.";
        assert this.compressionCodecResolver != null : "CompressionCodecResolver should never be null.";

        return new ImmutableJwtParser(new DefaultJwtParser(
            provider,
            signingKeyResolver,
            keyLocator,
            clock,
            allowedClockSkewMillis,
            expectedClaims,
            base64UrlDecoder,
            deserializer,
            compressionCodecResolver,
            extraSignatureAlgorithms,
            extraKeyAlgorithms,
            extraEncryptionAlgorithms
        ));
    }
}

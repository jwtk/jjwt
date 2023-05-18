/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AsymmetricJwk;
import io.jsonwebtoken.security.AsymmetricJwkBuilder;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPrivateJwkBuilder;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.EcPublicJwkBuilder;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPrivateJwkBuilder;
import io.jsonwebtoken.security.OctetPublicJwk;
import io.jsonwebtoken.security.OctetPublicJwkBuilder;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PrivateJwkBuilder;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.PublicJwkBuilder;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPrivateJwkBuilder;
import io.jsonwebtoken.security.RsaPublicJwk;
import io.jsonwebtoken.security.RsaPublicJwkBuilder;

import java.net.URI;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

abstract class AbstractAsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>,
        T extends AsymmetricJwkBuilder<K, J, T>>
        extends AbstractJwkBuilder<K, J, T> implements AsymmetricJwkBuilder<K, J, T> {

    protected Boolean applyX509KeyUse = null;
    private KeyUseStrategy keyUseStrategy = DefaultKeyUseStrategy.INSTANCE;

    private final DefaultX509Builder<T> x509Builder;

    public AbstractAsymmetricJwkBuilder(JwkContext<K> ctx) {
        super(ctx);
        this.x509Builder = new DefaultX509Builder<>(this.jwkContext, self(), MalformedKeyException.class);
    }

    AbstractAsymmetricJwkBuilder(AbstractAsymmetricJwkBuilder<?, ?, ?> b, JwkContext<K> ctx) {
        this(ctx);
        this.applyX509KeyUse = b.applyX509KeyUse;
        this.keyUseStrategy = b.keyUseStrategy;
    }

    @Override
    public T setPublicKeyUse(String use) {
        Assert.hasText(use, "publicKeyUse cannot be null or empty.");
        this.jwkContext.setPublicKeyUse(use);
        return self();
    }

    /*
    public T setKeyUseStrategy(KeyUseStrategy strategy) {
        this.keyUseStrategy = Assert.notNull(strategy, "KeyUseStrategy cannot be null.");
        return tthis();
    }
     */

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be null or empty.");
        return this.x509Builder.setX509CertificateChain(chain);
    }

    @Override
    public T setX509Url(URI uri) {
        Assert.notNull(uri, "X509Url cannot be null.");
        return this.x509Builder.setX509Url(uri);
    }

    /*
    @Override
    public T withX509KeyUse(boolean enable) {
        this.applyX509KeyUse = enable;
        return tthis();
    }
     */

    @Override
    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        return this.x509Builder.setX509CertificateSha1Thumbprint(thumbprint);
    }

    @Override
    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        return this.x509Builder.setX509CertificateSha256Thumbprint(thumbprint);
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        return this.x509Builder.withX509Sha1Thumbprint(enable);
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        return this.x509Builder.withX509Sha256Thumbprint(enable);
    }

    @Override
    public J build() {
        this.x509Builder.apply();
        return super.build();
    }

    private abstract static class DefaultPublicJwkBuilder<K extends PublicKey, L extends PrivateKey,
            J extends PublicJwk<K>, M extends PrivateJwk<L, K, J>, P extends PrivateJwkBuilder<L, K, J, M, P>,
            T extends PublicJwkBuilder<K, L, J, M, P, T>>
            extends AbstractAsymmetricJwkBuilder<K, J, T>
            implements PublicJwkBuilder<K, L, J, M, P, T> {

        DefaultPublicJwkBuilder(JwkContext<K> ctx) {
            super(ctx);
        }

        @Override
        public P setPrivateKey(L privateKey) {
            Assert.notNull(privateKey, "PrivateKey argument cannot be null.");
            final K publicKey = Assert.notNull(jwkContext.getKey(), "PublicKey cannot be null.");
            return newPrivateBuilder(newContext(privateKey)).setPublicKey(publicKey);
        }

        protected abstract P newPrivateBuilder(JwkContext<L> ctx);
    }

    private abstract static class DefaultPrivateJwkBuilder<K extends PrivateKey, L extends PublicKey,
            J extends PublicJwk<L>, M extends PrivateJwk<K, L, J>,
            T extends PrivateJwkBuilder<K, L, J, M, T>>
            extends AbstractAsymmetricJwkBuilder<K, M, T>
            implements PrivateJwkBuilder<K, L, J, M, T> {

        DefaultPrivateJwkBuilder(JwkContext<K> ctx) {
            super(ctx);
        }

        DefaultPrivateJwkBuilder(DefaultPublicJwkBuilder<L, K, J, M, ?, ?> b, JwkContext<K> ctx) {
            super(b, ctx);
            this.jwkContext.setPublicKey(b.jwkContext.getKey());
        }

        @Override
        public T setPublicKey(L publicKey) {
            this.jwkContext.setPublicKey(publicKey);
            return self();
        }
    }

    static class DefaultRsaPublicJwkBuilder
            extends DefaultPublicJwkBuilder<RSAPublicKey, RSAPrivateKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder, RsaPublicJwkBuilder>
            implements RsaPublicJwkBuilder {

        DefaultRsaPublicJwkBuilder(JwkContext<RSAPublicKey> ctx) {
            super(ctx);
        }

        @Override
        protected RsaPrivateJwkBuilder newPrivateBuilder(JwkContext<RSAPrivateKey> ctx) {
            return new DefaultRsaPrivateJwkBuilder(this, ctx);
        }
    }

    static class DefaultEcPublicJwkBuilder
            extends DefaultPublicJwkBuilder<ECPublicKey, ECPrivateKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder, EcPublicJwkBuilder>
            implements EcPublicJwkBuilder {
        DefaultEcPublicJwkBuilder(JwkContext<ECPublicKey> src) {
            super(src);
        }

        @Override
        protected EcPrivateJwkBuilder newPrivateBuilder(JwkContext<ECPrivateKey> ctx) {
            return new DefaultEcPrivateJwkBuilder(this, ctx);
        }
    }

    static class DefaultOctetPublicJwkBuilder<A extends PublicKey, B extends PrivateKey>
            extends DefaultPublicJwkBuilder<A, B, OctetPublicJwk<A>, OctetPrivateJwk<B, A>,
            OctetPrivateJwkBuilder<B, A>, OctetPublicJwkBuilder<A, B>>
            implements OctetPublicJwkBuilder<A, B> {
        DefaultOctetPublicJwkBuilder(JwkContext<A> ctx) {
            super(ctx);
            EdwardsCurve.assertEdwards(ctx.getKey());
        }

        @Override
        protected OctetPrivateJwkBuilder<B, A> newPrivateBuilder(JwkContext<B> ctx) {
            return new DefaultOctetPrivateJwkBuilder<>(this, ctx);
        }
    }

    static class DefaultRsaPrivateJwkBuilder
            extends DefaultPrivateJwkBuilder<RSAPrivateKey, RSAPublicKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder>
            implements RsaPrivateJwkBuilder {
        DefaultRsaPrivateJwkBuilder(JwkContext<RSAPrivateKey> src) {
            super(src);
        }

        DefaultRsaPrivateJwkBuilder(DefaultRsaPublicJwkBuilder b, JwkContext<RSAPrivateKey> ctx) {
            super(b, ctx);
        }
    }

    static class DefaultEcPrivateJwkBuilder
            extends DefaultPrivateJwkBuilder<ECPrivateKey, ECPublicKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder>
            implements EcPrivateJwkBuilder {
        DefaultEcPrivateJwkBuilder(JwkContext<ECPrivateKey> src) {
            super(src);
        }

        DefaultEcPrivateJwkBuilder(DefaultEcPublicJwkBuilder b, JwkContext<ECPrivateKey> ctx) {
            super(b, ctx);
        }
    }

    static class DefaultOctetPrivateJwkBuilder<A extends PrivateKey, B extends PublicKey>
            extends DefaultPrivateJwkBuilder<A, B, OctetPublicJwk<B>, OctetPrivateJwk<A, B>,
            OctetPrivateJwkBuilder<A, B>> implements OctetPrivateJwkBuilder<A, B> {
        DefaultOctetPrivateJwkBuilder(JwkContext<A> src) {
            super(src);
            EdwardsCurve.assertEdwards(src.getKey());
        }

        DefaultOctetPrivateJwkBuilder(DefaultOctetPublicJwkBuilder<B, A> b, JwkContext<A> ctx) {
            super(b, ctx);
            EdwardsCurve.assertEdwards(ctx.getKey());
            EdwardsCurve.assertEdwards(ctx.getPublicKey());
        }
    }
}

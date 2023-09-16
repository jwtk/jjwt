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

import io.jsonwebtoken.impl.ParameterMap;
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

abstract class AbstractAsymmetricJwkBuilder<K extends Key, J extends AsymmetricJwk<K>, T extends AsymmetricJwkBuilder<K, J, T>>
        extends AbstractJwkBuilder<K, J, T> implements AsymmetricJwkBuilder<K, J, T> {

    protected Boolean applyX509KeyUse = null;
    private KeyUseStrategy keyUseStrategy = DefaultKeyUseStrategy.INSTANCE;

    private final X509BuilderSupport x509;

    public AbstractAsymmetricJwkBuilder(JwkContext<K> ctx) {
        super(ctx);
        ParameterMap map = Assert.isInstanceOf(ParameterMap.class, this.DELEGATE);
        this.x509 = new X509BuilderSupport(map, MalformedKeyException.class);
    }

    AbstractAsymmetricJwkBuilder(AbstractAsymmetricJwkBuilder<?, ?, ?> b, JwkContext<K> ctx) {
        this(ctx);
        this.applyX509KeyUse = b.applyX509KeyUse;
        this.keyUseStrategy = b.keyUseStrategy;
    }

    @Override
    public T publicKeyUse(String use) {
        Assert.hasText(use, "publicKeyUse cannot be null or empty.");
        this.DELEGATE.setPublicKeyUse(use);
        return self();
    }

    /*
    public T setKeyUseStrategy(KeyUseStrategy strategy) {
        this.keyUseStrategy = Assert.notNull(strategy, "KeyUseStrategy cannot be null.");
        return tthis();
    }
     */

    @Override
    public T x509CertificateChain(List<X509Certificate> chain) {
        Assert.notEmpty(chain, "X509Certificate chain cannot be null or empty.");
        this.x509.x509CertificateChain(chain);
        return self();
    }

    @Override
    public T x509Url(URI uri) {
        Assert.notNull(uri, "X509Url cannot be null.");
        this.x509.x509Url(uri);
        return self();
    }

    /*
    @Override
    public T withX509KeyUse(boolean enable) {
        this.applyX509KeyUse = enable;
        return tthis();
    }
     */

    @Override
    public T x509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.x509.x509CertificateSha1Thumbprint(thumbprint);
        return self();
    }

    @Override
    public T x509CertificateSha256Thumbprint(byte[] thumbprint) {
        this.x509.x509CertificateSha256Thumbprint(thumbprint);
        return self();
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        this.x509.withX509Sha1Thumbprint(enable);
        return self();
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        this.x509.withX509Sha256Thumbprint(enable);
        return self();
    }

    @Override
    public J build() {
        this.x509.apply();
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
        public P privateKey(L privateKey) {
            Assert.notNull(privateKey, "PrivateKey argument cannot be null.");
            final K publicKey = Assert.notNull(DELEGATE.getKey(), "PublicKey cannot be null.");
            return newPrivateBuilder(newContext(privateKey)).publicKey(publicKey);
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
            this.DELEGATE.setPublicKey(b.DELEGATE.getKey());
        }

        @Override
        public T publicKey(L publicKey) {
            this.DELEGATE.setPublicKey(publicKey);
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

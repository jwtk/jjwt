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

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AsymmetricJwk;
import io.jsonwebtoken.security.AsymmetricJwkBuilder;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPrivateJwkBuilder;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.EcPublicJwkBuilder;
import io.jsonwebtoken.security.MalformedKeyException;
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
import java.util.Set;

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

    AbstractAsymmetricJwkBuilder(AbstractAsymmetricJwkBuilder<?, ?, ?> b, K key, Set<Field<?>> fields) {
        super(new DefaultJwkContext<>(fields, b.jwkContext, key));
        this.x509Builder = new DefaultX509Builder<>(this.jwkContext, self(), MalformedKeyException.class);
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
//        if (applyX509KeyUse == null) { //if not specified, enable by default if possible:
//            applyX509KeyUse = firstCert != null && !Strings.hasText(this.jwkContext.getPublicKeyUse());
//        }

//            if (applyX509KeyUse) {
//                KeyUsage usage = new KeyUsage(firstCert);
//                String use = keyUseStrategy.toJwkValue(usage);
//                if (Strings.hasText(use)) {
//                    setPublicKeyUse(use);
//                }
//            }
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
            return newPrivateBuilder(privateKey).setPublicKey(publicKey);
        }

        protected abstract P newPrivateBuilder(L privateKey);
    }

    private abstract static class DefaultPrivateJwkBuilder<K extends PrivateKey, L extends PublicKey,
            J extends PublicJwk<L>, M extends PrivateJwk<K, L, J>,
            T extends PrivateJwkBuilder<K, L, J, M, T>>
            extends AbstractAsymmetricJwkBuilder<K, M, T>
            implements PrivateJwkBuilder<K, L, J, M, T> {

        DefaultPrivateJwkBuilder(JwkContext<K> ctx) {
            super(ctx);
        }

        DefaultPrivateJwkBuilder(DefaultPublicJwkBuilder<L, K, J, M, ?, ?> b, K key, Set<Field<?>> fields) {
            super(b, key, fields);
            this.jwkContext.setPublicKey(b.jwkContext.getKey());
        }

        @Override
        public T setPublicKey(L publicKey) {
            this.jwkContext.setPublicKey(publicKey);
            return self();
        }
    }

    static class DefaultEcPublicJwkBuilder
            extends DefaultPublicJwkBuilder<ECPublicKey, ECPrivateKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder, EcPublicJwkBuilder>
            implements EcPublicJwkBuilder {

        DefaultEcPublicJwkBuilder(JwkContext<?> src, ECPublicKey key) {
            super(new DefaultJwkContext<>(DefaultEcPublicJwk.FIELDS, src, key));
        }

        @Override
        protected EcPrivateJwkBuilder newPrivateBuilder(ECPrivateKey key) {
            return new DefaultEcPrivateJwkBuilder(this, key);
        }
    }

    static class DefaultRsaPublicJwkBuilder
            extends DefaultPublicJwkBuilder<RSAPublicKey, RSAPrivateKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder, RsaPublicJwkBuilder>
            implements RsaPublicJwkBuilder {

        DefaultRsaPublicJwkBuilder(JwkContext<?> ctx, RSAPublicKey key) {
            super(new DefaultJwkContext<>(DefaultRsaPublicJwk.FIELDS, ctx, key));
        }

        @Override
        protected RsaPrivateJwkBuilder newPrivateBuilder(RSAPrivateKey key) {
            return new DefaultRsaPrivateJwkBuilder(this, key);
        }
    }

    static class DefaultEcPrivateJwkBuilder
            extends DefaultPrivateJwkBuilder<ECPrivateKey, ECPublicKey, EcPublicJwk, EcPrivateJwk, EcPrivateJwkBuilder>
            implements EcPrivateJwkBuilder {

        DefaultEcPrivateJwkBuilder(JwkContext<?> src, ECPrivateKey key) {
            super(new DefaultJwkContext<>(DefaultEcPrivateJwk.FIELDS, src, key));
        }

        DefaultEcPrivateJwkBuilder(DefaultEcPublicJwkBuilder b, ECPrivateKey key) {
            super(b, key, DefaultEcPrivateJwk.FIELDS);
        }
    }

    static class DefaultRsaPrivateJwkBuilder
            extends DefaultPrivateJwkBuilder<RSAPrivateKey, RSAPublicKey, RsaPublicJwk, RsaPrivateJwk, RsaPrivateJwkBuilder>
            implements RsaPrivateJwkBuilder {

        DefaultRsaPrivateJwkBuilder(JwkContext<?> src, RSAPrivateKey key) {
            super(new DefaultJwkContext<>(DefaultRsaPrivateJwk.FIELDS, src, key));
        }

        DefaultRsaPrivateJwkBuilder(DefaultRsaPublicJwkBuilder b, RSAPrivateKey key) {
            super(b, key, DefaultRsaPrivateJwk.FIELDS);
        }
    }
}

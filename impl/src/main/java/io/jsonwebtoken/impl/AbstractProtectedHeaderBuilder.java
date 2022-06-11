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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.impl.security.DefaultX509Builder;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractProtectedHeaderBuilder<H extends ProtectedHeader<H>,
        T extends ProtectedHeaderBuilder<H, T>>
        extends AbstractHeaderBuilder<H, T> implements ProtectedHeaderBuilder<H, T> {

    private DefaultX509Builder<T> x509Builder;

    @Override
    protected void onNewHeader(H header) {
        this.x509Builder = new DefaultX509Builder<>(header, tthis(), IllegalStateException.class);
    }

    @Override
    public T setJwkSetUrl(URI uri) {
        this.header.setJwkSetUrl(uri);
        return tthis();
    }

    @Override
    public T setJwk(PublicJwk<?> jwk) {
        this.header.setJwk(jwk);
        return tthis();
    }

    @Override
    public T setKeyId(String kid) {
        this.header.setKeyId(kid);
        return tthis();
    }

    @Override
    public T setX509Url(URI uri) {
        return this.x509Builder.setX509Url(uri);
    }

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        return this.x509Builder.setX509CertificateChain(chain);
    }

    @Override
    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.header.setX509CertificateSha1Thumbprint(thumbprint);
        return tthis();
    }

    @Override
    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        this.header.setX509CertificateSha256Thumbprint(thumbprint);
        return tthis();
    }

    @Override
    public T setCritical(Set<String> crit) {
        this.header.setCritical(crit);
        return tthis();
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        return x509Builder.withX509Sha1Thumbprint(enable);
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        return x509Builder.withX509Sha256Thumbprint(enable);
    }

    @Override
    public H build() {
        this.x509Builder.apply();
        return this.header;
    }
}

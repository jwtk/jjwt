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

import io.jsonwebtoken.DynamicHeaderBuilder;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.impl.security.DefaultX509Builder;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultDynamicHeaderBuilder implements DynamicHeaderBuilder {

    private Header<?> header;

    private DefaultX509Builder<DynamicHeaderBuilder> x509Builder;

    public DefaultDynamicHeaderBuilder() {
        this.header = new DefaultUnprotectedHeader();
        this.x509Builder = null;
    }

    private ProtectedHeader<?> ensureProtected() {
        ProtectedHeader<?> ph;
        if (this.header instanceof ProtectedHeader<?>) {
            ph = (ProtectedHeader<?>) this.header;
        } else {
            this.header = ph = new DefaultJwsHeader(this.header);
            this.x509Builder = new DefaultX509Builder<DynamicHeaderBuilder>(ph, this, IllegalStateException.class);
        }
        return ph;
    }

    private JweHeader ensureJwe() {
        JweHeader h;
        if (this.header instanceof JweHeader) {
            h = (JweHeader) this.header;
        } else {
            this.header = h = new DefaultJweHeader(this.header);
            this.x509Builder = new DefaultX509Builder<DynamicHeaderBuilder>(h, this, IllegalStateException.class);
        }
        return h;
    }

    @Override
    public DynamicHeaderBuilder put(String key, Object value) {
        this.header.put(key, value);
        return this;
    }

    @Override
    public DynamicHeaderBuilder remove(String key) {
        this.header.remove(key);
        return this;
    }

    @Override
    public DynamicHeaderBuilder putAll(Map<? extends String, ?> m) {
        this.header.putAll(m);
        return this;
    }

    @Override
    public DynamicHeaderBuilder clear() {
        this.header.clear();
        return this;
    }

    @Override
    public DynamicHeaderBuilder setType(String typ) {
        this.header.setType(typ);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setContentType(String cty) {
        this.header.setContentType(cty);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setAlgorithm(String alg) {
        this.header.setAlgorithm(alg);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setCompressionAlgorithm(String zip) {
        this.header.setCompressionAlgorithm(zip);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setJwkSetUrl(URI uri) {
        ensureProtected().setJwkSetUrl(uri);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setJwk(PublicJwk<?> jwk) {
        ensureProtected().setJwk(jwk);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setKeyId(String kid) {
        ensureProtected().setKeyId(kid);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setCritical(Set<String> crit) {
        ensureProtected().setCritical(crit);
        return this;
    }

    @Override
    public DynamicHeaderBuilder withX509Sha1Thumbprint(boolean enable) {
        ensureProtected();
        return this.x509Builder.withX509Sha1Thumbprint(enable);
    }

    @Override
    public DynamicHeaderBuilder withX509Sha256Thumbprint(boolean enable) {
        ensureProtected();
        return this.x509Builder.withX509Sha256Thumbprint(enable);
    }

    @Override
    public DynamicHeaderBuilder setX509Url(URI uri) {
        ensureProtected();
        return this.x509Builder.setX509Url(uri);
    }

    @Override
    public DynamicHeaderBuilder setX509CertificateChain(List<X509Certificate> chain) {
        ensureProtected();
        return this.x509Builder.setX509CertificateChain(chain);
    }

    @Override
    public DynamicHeaderBuilder setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        ensureProtected();
        return this.x509Builder.setX509CertificateSha1Thumbprint(thumbprint);
    }

    @Override
    public DynamicHeaderBuilder setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        ensureProtected();
        return this.x509Builder.setX509CertificateSha256Thumbprint(thumbprint);
    }

    @Override
    public DynamicHeaderBuilder setAgreementPartyUInfo(byte[] info) {
        ensureJwe().setAgreementPartyUInfo(info);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setAgreementPartyUInfo(String info) {
        ensureJwe().setAgreementPartyUInfo(info);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setAgreementPartyVInfo(byte[] info) {
        ensureJwe().setAgreementPartyVInfo(info);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setAgreementPartyVInfo(String info) {
        ensureJwe().setAgreementPartyVInfo(info);
        return this;
    }

    @Override
    public DynamicHeaderBuilder setPbes2Count(int count) {
        ensureJwe().setPbes2Count(count);
        return this;
    }

    @Override
    public Header<?> build() {
        if (this.x509Builder != null) {
            this.x509Builder.apply();
        }
        return this.header;
    }
}

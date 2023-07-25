/*
 * Copyright (C) 2023 jsonwebtoken.io
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

import io.jsonwebtoken.JweHeaderMutator;
import io.jsonwebtoken.impl.lang.DelegatingMapMutator;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.security.X509BuilderSupport;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * @param <T> return type for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeaderMutator<T extends JweHeaderMutator<T>>
        extends DelegatingMapMutator<String, Object, FieldMap, T> implements JweHeaderMutator<T> {

    protected X509BuilderSupport x509;

    public DefaultJweHeaderMutator() {
        // Any type of header can be created, but JWE fields reflect all potential standard ones, so we use those fields
        // to catch any value being set, especially through generic 'put' or 'putAll' methods:
        super(new FieldMap(DefaultJweHeader.FIELDS));
        clear(); // initialize new X509Builder
    }

    public DefaultJweHeaderMutator(DefaultJweHeaderMutator<?> src) {
        super(src.DELEGATE);
        this.x509 = src.x509;
    }

    // =============================================================
    // MapMutator methods
    // =============================================================

    private T put(Field<?> field, Object value) {
        this.DELEGATE.put(field, value);
        return self();
    }

    @Override
    public void clear() {
        super.clear();
        this.x509 = new X509BuilderSupport(this.DELEGATE, IllegalStateException.class);
    }

    // =============================================================
    // JWT Header methods
    // =============================================================

    @Override
    public T setAlgorithm(String alg) {
        return put(DefaultHeader.ALGORITHM, alg);
    }

    @Override
    public T setContentType(String cty) {
        return put(DefaultHeader.CONTENT_TYPE, cty);
    }

    @Override
    public T setType(String typ) {
        return put(DefaultHeader.TYPE, typ);
    }

    @Override
    public T setCompressionAlgorithm(String zip) {
        return put(DefaultHeader.COMPRESSION_ALGORITHM, zip);
    }

    // =============================================================
    // Protected Header methods
    // =============================================================

    @Override
    public T setJwkSetUrl(URI uri) {
        return put(DefaultProtectedHeader.JKU, uri);
    }

    @Override
    public T setJwk(PublicJwk<?> jwk) {
        return put(DefaultProtectedHeader.JWK, jwk);
    }

    @Override
    public T setKeyId(String kid) {
        return put(DefaultProtectedHeader.KID, kid);
    }

    @Override
    public T setCritical(Set<String> crit) {
        return put(DefaultProtectedHeader.CRIT, crit);
    }


    // =============================================================
    // X.509 methods
    // =============================================================

    @Override
    public T setX509Url(URI uri) {
        this.x509.setX509Url(uri);
        return self();
    }

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        this.x509.setX509CertificateChain(chain);
        return self();
    }

    @Override
    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.x509.setX509CertificateSha1Thumbprint(thumbprint);
        return self();
    }

    @Override
    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        this.x509.setX509CertificateSha256Thumbprint(thumbprint);
        return self();
    }

    // =============================================================
    // JWE Header methods
    // =============================================================

    @Override
    public T setAgreementPartyUInfo(byte[] info) {
        return put(DefaultJweHeader.APU, info);
    }

    @Override
    public T setAgreementPartyUInfo(String info) {
        return setAgreementPartyUInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public T setAgreementPartyVInfo(byte[] info) {
        return put(DefaultJweHeader.APV, info);
    }

    @Override
    public T setAgreementPartyVInfo(String info) {
        return setAgreementPartyVInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public T setPbes2Count(int count) {
        return put(DefaultJweHeader.P2C, count);
    }
}

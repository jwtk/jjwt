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
import io.jsonwebtoken.impl.lang.Parameter;
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
        extends DelegatingMapMutator<String, Object, ParameterMap, T> implements JweHeaderMutator<T> {

    protected X509BuilderSupport x509;

    public DefaultJweHeaderMutator() {
        // Any type of header can be created, but JWE parameters reflect all potential standard ones, so we use those
        // params to catch any value being set, especially through generic 'put' or 'putAll' methods:
        super(new ParameterMap(DefaultJweHeader.PARAMS));
        clear(); // initialize new X509Builder
    }

    public DefaultJweHeaderMutator(DefaultJweHeaderMutator<?> src) {
        super(src.DELEGATE);
        this.x509 = src.x509;
    }

    // =============================================================
    // MapMutator methods
    // =============================================================

    private <F> T put(Parameter<F> param, F value) {
        this.DELEGATE.put(param, value);
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

//    @Override
//    public T algorithm(String alg) {
//        return put(DefaultHeader.ALGORITHM, alg);
//    }

    @Override
    public T contentType(String cty) {
        return put(DefaultHeader.CONTENT_TYPE, cty);
    }

    @Override
    public T type(String typ) {
        return put(DefaultHeader.TYPE, typ);
    }

    @Override
    public T setType(String typ) {
        return type(typ);
    }

    @Override
    public T setContentType(String cty) {
        return contentType(cty);
    }

    @Override
    public T setCompressionAlgorithm(String zip) {
        return put(DefaultHeader.COMPRESSION_ALGORITHM, zip);
    }

    // =============================================================
    // Protected Header methods
    // =============================================================

    @Override
    public T critical(Set<String> crit) {
        return put(DefaultProtectedHeader.CRIT, crit);
    }

    @Override
    public T jwk(PublicJwk<?> jwk) {
        return put(DefaultProtectedHeader.JWK, jwk);
    }

    @Override
    public T jwkSetUrl(URI uri) {
        return put(DefaultProtectedHeader.JKU, uri);
    }

    @Override
    public T keyId(String kid) {
        return put(DefaultProtectedHeader.KID, kid);
    }

    @Override
    public T setKeyId(String kid) {
        return keyId(kid);
    }

    @Override
    public T setAlgorithm(String alg) {
        return put(DefaultHeader.ALGORITHM, alg);
    }

    // =============================================================
    // X.509 methods
    // =============================================================

    @Override
    public T x509Url(URI uri) {
        this.x509.x509Url(uri);
        return self();
    }

    @Override
    public T x509CertificateChain(List<X509Certificate> chain) {
        this.x509.x509CertificateChain(chain);
        return self();
    }

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

    // =============================================================
    // JWE Header methods
    // =============================================================

    @Override
    public T agreementPartyUInfo(byte[] info) {
        return put(DefaultJweHeader.APU, info);
    }

    @Override
    public T agreementPartyUInfo(String info) {
        return agreementPartyUInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public T agreementPartyVInfo(byte[] info) {
        return put(DefaultJweHeader.APV, info);
    }

    @Override
    public T agreementPartyVInfo(String info) {
        return agreementPartyVInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public T pbes2Count(int count) {
        return put(DefaultJweHeader.P2C, count);
    }
}

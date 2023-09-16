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

import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.security.X509Mutator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public class AbstractX509Context<T extends X509Mutator<T>> extends ParameterMap implements X509Context<T> {

    public AbstractX509Context(Set<Parameter<?>> params) {
        super(params);
    }

    @SuppressWarnings("unchecked")
    protected T self() {
        return (T) this;
    }

    @Override
    public URI getX509Url() {
        return get(AbstractAsymmetricJwk.X5U);
    }

    @Override
    public T x509Url(URI uri) {
        put(AbstractAsymmetricJwk.X5U, uri);
        return self();
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(AbstractAsymmetricJwk.X5C);
    }

    @Override
    public T x509CertificateChain(List<X509Certificate> chain) {
        put(AbstractAsymmetricJwk.X5C, chain);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(AbstractAsymmetricJwk.X5T);
    }

    @Override
    public T x509CertificateSha1Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T, thumbprint);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(AbstractAsymmetricJwk.X5T_S256);
    }

    @Override
    public T x509CertificateSha256Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T_S256, thumbprint);
        return self();
    }
}

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
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.impl.security.AbstractJwk;
import io.jsonwebtoken.impl.security.JwkConverter;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.X509Mutator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Header implementation satisfying shared JWS and JWE header parameter requirements.  Header parameters specific to
 * either JWE or JWS will be defined in respective subclasses.
 *
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractProtectedHeader<T extends AbstractProtectedHeader<T>> extends AbstractHeader<T> implements ProtectedHeader, X509Mutator<T> {

    static final Field<URI> JKU = Fields.uri("jku", "JWK Set URL");

    @SuppressWarnings("unchecked")
    static final Field<PublicJwk<?>> JWK = Fields.builder((Class<PublicJwk<?>>) (Class<?>) PublicJwk.class)
            .setId("jwk").setName("JSON Web Key")
            .setConverter(JwkConverter.PUBLIC_JWK).build();
    static final Field<Set<String>> CRIT = Fields.stringSet("crit", "Critical");

    static final Registry<String, Field<?>> FIELDS = Fields.registry(AbstractHeader.FIELDS,
            CRIT, JKU, JWK, AbstractJwk.KID, AbstractAsymmetricJwk.X5U, AbstractAsymmetricJwk.X5C,
            AbstractAsymmetricJwk.X5T, AbstractAsymmetricJwk.X5T_S256);

    protected AbstractProtectedHeader(Registry<String, Field<?>> fields) {
        super(fields);
    }

    protected AbstractProtectedHeader(Registry<String, Field<?>> fields, Map<String, ?> values) {
        super(fields, values);
    }

    public String getKeyId() {
        return idiomaticGet(AbstractJwk.KID);
    }

    public T setKeyId(String kid) {
        put(AbstractJwk.KID, kid);
        return tthis();
    }

    public URI getJwkSetUrl() {
        return idiomaticGet(JKU);
    }

    public T setJwkSetUrl(URI uri) {
        put(JKU, uri);
        return tthis();
    }

    public PublicJwk<?> getJwk() {
        return idiomaticGet(JWK);
    }

    public T setJwk(PublicJwk<?> jwk) {
        put(JWK, jwk);
        return tthis();
    }

    public URI getX509Url() {
        return idiomaticGet(AbstractAsymmetricJwk.X5U);
    }

    public T setX509Url(URI uri) {
        put(AbstractAsymmetricJwk.X5U, uri);
        return tthis();
    }

    public List<X509Certificate> getX509CertificateChain() {
        return idiomaticGet(AbstractAsymmetricJwk.X5C);
    }

    public T setX509CertificateChain(List<X509Certificate> chain) {
        put(AbstractAsymmetricJwk.X5C, chain);
        return tthis();
    }

    public byte[] getX509CertificateSha1Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T);
    }

    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T, thumbprint);
        return tthis();
    }

    public byte[] getX509CertificateSha256Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T_S256);
    }

    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T_S256, thumbprint);
        return tthis();
    }

    public Set<String> getCritical() {
        return idiomaticGet(CRIT);
    }

    public T setCritical(Set<String> crit) {
        put(CRIT, crit);
        return tthis();
    }
}

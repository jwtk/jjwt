/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.impl.security.AbstractJwk;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultHeader<T extends Header<T>> extends JwtMap implements Header<T> {

    static final Field<String> TYPE = Fields.string(Header.TYPE, "Type");
    static final Field<String> CONTENT_TYPE = Fields.string(Header.CONTENT_TYPE, "Content Type");
    static final Field<String> ALGORITHM = Fields.string(Header.ALGORITHM, "Algorithm");
    static final Field<String> COMPRESSION_ALGORITHM = Fields.string(Header.COMPRESSION_ALGORITHM, "Compression Algorithm");
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated // TODO: remove for 1.0.0:
    static final Field<String> DEPRECATED_COMPRESSION_ALGORITHM = Fields.string(Header.DEPRECATED_COMPRESSION_ALGORITHM, "Deprecated Compression Algorithm");
    static final Field<URI> JKU = Fields.uri("jku", "JWK Set URL");
    @SuppressWarnings("rawtypes")
    static final Field<PublicJwk> JWK = Fields.builder(PublicJwk.class).setId("jwk").setName("JSON Web Key").build();
    static final Field<Set<String>> CRIT = Fields.stringSet("crit", "Critical");

    static final Set<Field<?>> FIELDS = Collections.<Field<?>>setOf(TYPE, CONTENT_TYPE, ALGORITHM, COMPRESSION_ALGORITHM);
    static final Set<Field<?>> CHILD_FIELDS = Collections.concat(FIELDS, JKU, JWK, CRIT, AbstractJwk.KID,
        AbstractAsymmetricJwk.X5U, AbstractAsymmetricJwk.X5C, AbstractAsymmetricJwk.X5T, AbstractAsymmetricJwk.X5T_S256);

    protected DefaultHeader(Set<Field<?>> fieldSet) {
        super(fieldSet);
    }

    protected DefaultHeader(Set<Field<?>> fieldSet, Map<String, ?> values) {
        super(fieldSet, values);
    }

    public DefaultHeader() {
        this(FIELDS);
    }

    public DefaultHeader(Map<String, ?> map) {
        this(FIELDS, map);
    }

    @SuppressWarnings("unchecked")
    protected T tthis() {
        return (T) this;
    }

    @Override
    public String getType() {
        return idiomaticGet(TYPE);
    }

    @Override
    public T setType(String typ) {
        put(TYPE.getId(), typ);
        return tthis();
    }

    @Override
    public String getContentType() {
        return idiomaticGet(CONTENT_TYPE);
    }

    @Override
    public T setContentType(String cty) {
        put(CONTENT_TYPE.getId(), cty);
        return tthis();
    }

    @Override
    public String getAlgorithm() {
        return idiomaticGet(ALGORITHM);
    }

    @Override
    public T setAlgorithm(String alg) {
        put(ALGORITHM.getId(), alg);
        return tthis();
    }

    @Override
    public String getCompressionAlgorithm() {
        String s = idiomaticGet(COMPRESSION_ALGORITHM);
        if (!Strings.hasText(s)) {
            s = idiomaticGet(DEPRECATED_COMPRESSION_ALGORITHM);
        }
        return s;
    }

    @Override
    public T setCompressionAlgorithm(String compressionAlgorithm) {
        put(COMPRESSION_ALGORITHM.getId(), compressionAlgorithm);
        return tthis();
    }

    public String getKeyId() {
        return idiomaticGet(AbstractJwk.KID);
    }

    public T setKeyId(String kid) {
        put(AbstractJwk.KID.getId(), kid);
        return tthis();
    }

    public URI getJwkSetUrl() {
        return idiomaticGet(JKU);
    }

    public T setJwkSetUrl(URI uri) {
        put(JKU.getId(), uri);
        return tthis();
    }

    public PublicJwk<?> getJwk() {
        return idiomaticGet(JWK);
    }

    public T setJwk(PublicJwk<?> jwk) {
        put(JWK.getId(), jwk);
        return tthis();
    }

    public URI getX509Url() {
        return idiomaticGet(AbstractAsymmetricJwk.X5U);
    }

    public T setX509Url(URI uri) {
        put(AbstractAsymmetricJwk.X5U.getId(), uri);
        return tthis();
    }

    public List<X509Certificate> getX509CertificateChain() {
        return idiomaticGet(AbstractAsymmetricJwk.X5C);
    }

    public T setX509CertificateChain(List<X509Certificate> chain) {
        put(AbstractAsymmetricJwk.X5C.getId(), chain);
        return tthis();
    }

    public byte[] getX509CertificateSha1Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T);
    }

    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T.getId(), thumbprint);
        return tthis();
    }

    public T computeX509CertificateSha1Thumbprint() {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    public byte[] getX509CertificateSha256Thumbprint() {
        return idiomaticGet(AbstractAsymmetricJwk.X5T_S256);
    }

    public T setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        put(AbstractAsymmetricJwk.X5T_S256.getId(), thumbprint);
        return tthis();
    }

    public T computeX509CertificateSha256Thumbprint() {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    public Set<String> getCritical() {
        return idiomaticGet(CRIT);
    }

    public T setCritical(Set<String> crit) {
        put(CRIT.getId(), crit);
        return tthis();
    }
}

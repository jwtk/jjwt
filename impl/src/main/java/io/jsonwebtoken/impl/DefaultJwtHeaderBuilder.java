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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtHeaderBuilder;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.security.DefaultX509Builder;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implementor's note: this implementation implements {@link JweHeader} to allow reading of properties from current
 * builder state and to allow the builder to act as a header in certain contexts (such as during KeyAlgorithm
 * requests), but this notion that a builder 'isA' header is not to be exposed to the public API.
 *
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJwtHeaderBuilder implements JwtHeaderBuilder {

    private final JwtBuilder jwtBuilder;

    private final FieldMap params;

    private DefaultX509Builder<JwtHeaderBuilder> x509Builder;

    public DefaultJwtHeaderBuilder(JwtBuilder jwtBuilder) {
        // Any type of header can be created, but JWE fields reflect all potential standard ones, so we use those fields
        // to catch any value being set, especially through generic 'put' or 'putAll' methods:
        this.jwtBuilder = Assert.notNull(jwtBuilder, "JwtBuilder cannot be null.");
        this.params = new FieldMap(DefaultJweHeader.FIELDS);
        clear(); // initialize new X509Builder
    }

    // ====================== Map Methods =======================

    @Override
    public int size() {
        return this.params.size();
    }

    @Override
    public boolean isEmpty() {
        return this.params.isEmpty();
    }

    @SuppressWarnings("SuspiciousMethodCalls")
    @Override
    public boolean containsKey(Object key) {
        return this.params.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return this.params.containsValue(value);
    }

    @SuppressWarnings("SuspiciousMethodCalls")
    @Override
    public Object get(Object key) {
        return this.params.get(key);
    }

    @Override
    public Set<String> keySet() {
        return this.params.keySet();
    }

    @Override
    public Collection<Object> values() {
        return this.params.values();
    }

    @Override
    public Set<Map.Entry<String, Object>> entrySet() {
        return this.params.entrySet();
    }

    @Override
    public JwtHeaderBuilder put(String key, Object value) {
        this.params.put(key, value);
        return this;
    }

    private JwtHeaderBuilder put(Field<?> field, Object value) {
        this.params.put(field, value);
        return this;
    }

    private <T> T get(Field<T> field) {
        return this.params.get(field);
    }

    @Override
    public JwtHeaderBuilder remove(String key) {
        this.params.remove(key);
        return this;
    }

    @Override
    public JwtHeaderBuilder putAll(Map<? extends String, ?> m) {
        this.params.putAll(m);
        return this;
    }

    @Override
    public JwtHeaderBuilder clear() {
        this.params.clear();
        this.x509Builder = new DefaultX509Builder<JwtHeaderBuilder>(this.params, this, IllegalStateException.class);
        return this;
    }

    // ====================== Header Methods =======================

    @Override
    public String getType() {
        return get(DefaultHeader.TYPE);
    }

    @Override
    public JwtHeaderBuilder setType(String typ) {
        return put(DefaultHeader.TYPE, typ);
    }

    @Override
    public String getContentType() {
        return get(DefaultHeader.CONTENT_TYPE);
    }

    @Override
    public JwtHeaderBuilder setContentType(String cty) {
        return put(DefaultHeader.CONTENT_TYPE, cty);
    }

    @Override
    public String getAlgorithm() {
        return get(DefaultHeader.ALGORITHM);
    }

    @Override
    public JwtHeaderBuilder setAlgorithm(String alg) {
        return put(DefaultHeader.ALGORITHM, alg);
    }

    @Override
    public String getCompressionAlgorithm() {
        return get(DefaultHeader.COMPRESSION_ALGORITHM);
    }

    @Override
    public JwtHeaderBuilder setCompressionAlgorithm(String zip) {
        return put(DefaultHeader.COMPRESSION_ALGORITHM, zip);
    }

    // ====================== Protected Header Methods =======================

    @Override
    public URI getJwkSetUrl() {
        return get(DefaultProtectedHeader.JKU);
    }

    @Override
    public JwtHeaderBuilder setJwkSetUrl(URI uri) {
        return put(DefaultProtectedHeader.JKU, uri);
    }

    @Override
    public PublicJwk<?> getJwk() {
        return get(DefaultProtectedHeader.JWK);
    }

    @Override
    public JwtHeaderBuilder setJwk(PublicJwk<?> jwk) {
        return put(DefaultProtectedHeader.JWK, jwk);
    }

    @Override
    public String getKeyId() {
        return get(DefaultProtectedHeader.KID);
    }

    @Override
    public JwtHeaderBuilder setKeyId(String kid) {
        return put(DefaultProtectedHeader.KID, kid);
    }

    @Override
    public Set<String> getCritical() {
        return get(DefaultProtectedHeader.CRIT);
    }

    @Override
    public JwtHeaderBuilder setCritical(Set<String> crit) {
        return put(DefaultProtectedHeader.CRIT, crit);
    }

    // ====================== X.509 Methods =======================

    @Override
    public JwtHeaderBuilder withX509Sha1Thumbprint(boolean enable) {
        return this.x509Builder.withX509Sha1Thumbprint(enable);
    }

    @Override
    public JwtHeaderBuilder withX509Sha256Thumbprint(boolean enable) {
        return this.x509Builder.withX509Sha256Thumbprint(enable);
    }

    @Override
    public URI getX509Url() {
        return get(DefaultProtectedHeader.X5U);
    }

    @Override
    public JwtHeaderBuilder setX509Url(URI uri) {
        return this.x509Builder.setX509Url(uri);
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(DefaultProtectedHeader.X5C);
    }

    @Override
    public JwtHeaderBuilder setX509CertificateChain(List<X509Certificate> chain) {
        return this.x509Builder.setX509CertificateChain(chain);
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(DefaultProtectedHeader.X5T);
    }

    @Override
    public JwtHeaderBuilder setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        return this.x509Builder.setX509CertificateSha1Thumbprint(thumbprint);
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(DefaultProtectedHeader.X5T_S256);
    }

    @Override
    public JwtHeaderBuilder setX509CertificateSha256Thumbprint(byte[] thumbprint) {
        return this.x509Builder.setX509CertificateSha256Thumbprint(thumbprint);
    }

    // ====================== JWE Header Methods =======================

    @Override
    public byte[] getAgreementPartyUInfo() {
        return get(DefaultJweHeader.APU);
    }

    @Override
    public JwtHeaderBuilder setAgreementPartyUInfo(byte[] info) {
        return put(DefaultJweHeader.APU, info);
    }

    @Override
    public JwtHeaderBuilder setAgreementPartyUInfo(String info) {
        return setAgreementPartyUInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return get(DefaultJweHeader.APV);
    }

    @Override
    public JwtHeaderBuilder setAgreementPartyVInfo(byte[] info) {
        return put(DefaultJweHeader.APV, info);
    }

    @Override
    public JwtHeaderBuilder setAgreementPartyVInfo(String info) {
        return setAgreementPartyVInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public Integer getPbes2Count() {
        return get(DefaultJweHeader.P2C);
    }

    @Override
    public JwtHeaderBuilder setPbes2Count(int count) {
        return put(DefaultJweHeader.P2C, count);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return get(DefaultJweHeader.ENCRYPTION_ALGORITHM);
    }

    @Override
    public PublicJwk<?> getEphemeralPublicKey() {
        return get(DefaultJweHeader.EPK);
    }

    @Override
    public byte[] getInitializationVector() {
        return get(DefaultJweHeader.IV);
    }

    @Override
    public byte[] getAuthenticationTag() {
        return get(DefaultJweHeader.TAG);
    }

    @Override
    public byte[] getPbes2Salt() {
        return get(DefaultJweHeader.P2S);
    }

    @Override
    public Header build() {

        this.x509Builder.apply(); // apply any X.509 values as necessary based on builder state

        //Use a copy constructor to ensure subsequent changes to builder state do not change the constructed header

        // Note: conditional sequence matters here: JWE has more specific requirements than JWS, so check that first:
        if (DefaultJweHeader.isCandidate(this.params)) {
            return new DefaultJweHeader(this.params);
        } else if (DefaultProtectedHeader.isCandidate(this.params)) {
            return new DefaultJwsHeader(this.params);
        } else {
            return new DefaultHeader(this.params);
        }
    }

    @Override
    public JwtBuilder and() {
        return this.jwtBuilder;
    }
}

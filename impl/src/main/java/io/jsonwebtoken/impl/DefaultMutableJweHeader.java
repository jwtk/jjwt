package io.jsonwebtoken.impl;

import io.jsonwebtoken.MutableJweHeader;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.security.X509BuilderSupport;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultMutableJweHeader<T extends MutableJweHeader<T>> implements MutableJweHeader<T> {

    protected final FieldMap params;

    protected X509BuilderSupport x509;

    public DefaultMutableJweHeader() {
        // Any type of header can be created, but JWE fields reflect all potential standard ones, so we use those fields
        // to catch any value being set, especially through generic 'put' or 'putAll' methods:
        this.params = new FieldMap(DefaultJweHeader.FIELDS);
        clear(); // initialize new X509Builder
    }

    public DefaultMutableJweHeader(DefaultMutableJweHeader<?> src) {
        this.params = src.params;
        this.x509 = src.x509;
    }

    @SuppressWarnings("unchecked")
    protected T self() {
        return (T) this;
    }

    // =============================================================
    // MapAccessor/MapMutator methods
    // =============================================================

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
    public T put(String key, Object value) {
        this.params.put(key, value);
        return self();
    }

    private T put(Field<?> field, Object value) {
        this.params.put(field, value);
        return self();
    }

    private <FT> FT get(Field<FT> field) {
        return this.params.get(field);
    }

    @Override
    public T remove(String key) {
        this.params.remove(key);
        return self();
    }

    @Override
    public T putAll(Map<? extends String, ?> m) {
        this.params.putAll(m);
        return self();
    }

    @Override
    public T clear() {
        this.params.clear();
        this.x509 = new X509BuilderSupport(this.params, IllegalStateException.class);
        return self();
    }

    // =============================================================
    // JWT Header methods
    // =============================================================

    @Override
    public String getAlgorithm() {
        return get(DefaultHeader.ALGORITHM);
    }

    @Override
    public T setAlgorithm(String alg) {
        return put(DefaultHeader.ALGORITHM, alg);
    }

    @Override
    public String getContentType() {
        return get(DefaultHeader.CONTENT_TYPE);
    }

    @Override
    public T setContentType(String cty) {
        return put(DefaultHeader.CONTENT_TYPE, cty);
    }

    @Override
    public String getType() {
        return get(DefaultHeader.TYPE);
    }

    @Override
    public T setType(String typ) {
        return put(DefaultHeader.TYPE, typ);
    }

    @Override
    public String getCompressionAlgorithm() {
        return get(DefaultHeader.COMPRESSION_ALGORITHM);
    }

    @Override
    public T setCompressionAlgorithm(String zip) {
        return put(DefaultHeader.COMPRESSION_ALGORITHM, zip);
    }

    // =============================================================
    // Protected Header methods
    // =============================================================

    @Override
    public URI getJwkSetUrl() {
        return get(DefaultProtectedHeader.JKU);
    }

    @Override
    public T setJwkSetUrl(URI uri) {
        return put(DefaultProtectedHeader.JKU, uri);
    }

    @Override
    public PublicJwk<?> getJwk() {
        return get(DefaultProtectedHeader.JWK);
    }

    @Override
    public T setJwk(PublicJwk<?> jwk) {
        return put(DefaultProtectedHeader.JWK, jwk);
    }

    @Override
    public String getKeyId() {
        return get(DefaultProtectedHeader.KID);
    }

    @Override
    public T setKeyId(String kid) {
        return put(DefaultProtectedHeader.KID, kid);
    }

    @Override
    public Set<String> getCritical() {
        return get(DefaultProtectedHeader.CRIT);
    }

    @Override
    public T setCritical(Set<String> crit) {
        return put(DefaultProtectedHeader.CRIT, crit);
    }


    // =============================================================
    // X.509 methods
    // =============================================================

    @Override
    public URI getX509Url() {
        return get(DefaultProtectedHeader.X5U);
    }

    @Override
    public T setX509Url(URI uri) {
        this.x509.setX509Url(uri);
        return self();
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(DefaultProtectedHeader.X5C);
    }

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        this.x509.setX509CertificateChain(chain);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(DefaultProtectedHeader.X5T);
    }

    @Override
    public T setX509CertificateSha1Thumbprint(byte[] thumbprint) {
        this.x509.setX509CertificateSha1Thumbprint(thumbprint);
        return self();
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(DefaultProtectedHeader.X5T_S256);
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
    public byte[] getAgreementPartyUInfo() {
        return get(DefaultJweHeader.APU);
    }

    @Override
    public T setAgreementPartyUInfo(byte[] info) {
        return put(DefaultJweHeader.APU, info);
    }

    @Override
    public T setAgreementPartyUInfo(String info) {
        return setAgreementPartyUInfo(Strings.utf8(Strings.clean(info)));
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return get(DefaultJweHeader.APV);
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
    public Integer getPbes2Count() {
        return get(DefaultJweHeader.P2C);
    }

    @Override
    public T setPbes2Count(int count) {
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
}

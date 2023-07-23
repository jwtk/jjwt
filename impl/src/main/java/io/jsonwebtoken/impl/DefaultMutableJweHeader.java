package io.jsonwebtoken.impl;

import io.jsonwebtoken.MutableJweHeader;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultMutableJweHeader extends DefaultJweHeaderMutator<MutableJweHeader> implements MutableJweHeader {

    public DefaultMutableJweHeader(DefaultJweHeaderMutator<?> src) {
        super(src);
    }

    // =============================================================
    // MapAccessor methods
    // =============================================================

    private <T> T get(Field<T> field) {
        return this.params.get(field);
    }

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
    public Map<String, Object> toMap() {
        return this.params.toMap();
    }

    // =============================================================
    // JWT Header methods
    // =============================================================

    @Override
    public String getAlgorithm() {
        return get(DefaultHeader.ALGORITHM);
    }

    @Override
    public String getContentType() {
        return get(DefaultHeader.CONTENT_TYPE);
    }

    @Override
    public String getType() {
        return get(DefaultHeader.TYPE);
    }

    @Override
    public String getCompressionAlgorithm() {
        return get(DefaultHeader.COMPRESSION_ALGORITHM);
    }

    // =============================================================
    // Protected Header methods
    // =============================================================

    @Override
    public URI getJwkSetUrl() {
        return get(DefaultProtectedHeader.JKU);
    }

    @Override
    public PublicJwk<?> getJwk() {
        return get(DefaultProtectedHeader.JWK);
    }

    @Override
    public String getKeyId() {
        return get(DefaultProtectedHeader.KID);
    }

    @Override
    public Set<String> getCritical() {
        return get(DefaultProtectedHeader.CRIT);
    }

    // =============================================================
    // X.509 methods
    // =============================================================

    @Override
    public URI getX509Url() {
        return get(DefaultProtectedHeader.X5U);
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(DefaultProtectedHeader.X5C);
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(DefaultProtectedHeader.X5T);
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(DefaultProtectedHeader.X5T_S256);
    }

    // =============================================================
    // JWE Header methods
    // =============================================================

    @Override
    public byte[] getAgreementPartyUInfo() {
        return get(DefaultJweHeader.APU);
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return get(DefaultJweHeader.APV);
    }

    @Override
    public Integer getPbes2Count() {
        return get(DefaultJweHeader.P2C);
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

package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AsymmetricJwk;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class AbstractAsymmetricJwk<V, K extends Key> extends DefaultJwk<K> implements AsymmetricJwk<Object, K> {

    private final String use;
    private final URI x509Url;
    private final List<X509Certificate> certChain;
    private final byte[] x509Sha1Thumbprint;
    private final byte[] x509Sha256Thumbprint;

    AbstractAsymmetricJwk(String type, String use, Set<String> operations, String algorithm, String id, URI x509Url, List<X509Certificate> certChain, byte[] x509Sha1Thumbprint, byte[] x509Sha256Thumbprint, K key, Map<String, ?> values) {
        super(type, operations, algorithm, id, key, values);
        this.use = use;
        this.x509Url = x509Url;
        this.certChain = certChain;
        this.x509Sha1Thumbprint = x509Sha1Thumbprint;
        this.x509Sha256Thumbprint = x509Sha256Thumbprint;
    }

    @Override
    public String getUse() {
        return this.use;
    }

    @Override
    public URI getX509Url() {
        return this.x509Url;
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return this.certChain;
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return this.x509Sha1Thumbprint;
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return this.x509Sha256Thumbprint;
    }

}
